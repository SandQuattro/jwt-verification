package jwtverification

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gurkankaymak/hocon"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"os"
	"strings"
)

var ErrInvalidKeyType = errors.New("invalid key type")
var ErrInvalidToken = errors.New("invalid token")

type KeyType int

const (
	PEM = iota
	DER
)

type JwtService struct {
	config  *hocon.Config
	logger  *logrus.Logger
	keyType KeyType
}

func New(config *hocon.Config, logger *logrus.Logger, keyType KeyType) *JwtService {
	return &JwtService{config: config, logger: logger, keyType: keyType}
}

func (s *JwtService) ValidateToken(tokenStr string, path string, redis *redis.Client) (jwt.MapClaims, bool, error) {
	var publicKeys []crypto.PublicKey

	var redisKeys [][]byte
	if redis != nil {
		keys, err := GetBase64DecodedKeysFromRedis(redis)
		if err != nil {
			return nil, false, err
		}
		redisKeys = keys
	} else {
		s.logger.Warn("redis disabled or not configured")
	}

	if redis == nil || len(redisKeys) == 0 {
		s.logger.Error("redis disabled or no keys in redis")
		switch s.keyType {
		case PEM:
			publicKey, err := s.readPublicPEMKey(path)
			if err != nil {
				return nil, false, err
			}
			publicKeys = append(publicKeys, publicKey)
		case DER:
			publicKey, err := s.readPublicDERKey(path)
			if err != nil {
				return nil, false, err
			}
			publicKeys = append(publicKeys, publicKey)
		default:
			return nil, false, ErrInvalidKeyType
		}
	} else {
		for _, base64DecodedKey := range redisKeys {
			switch s.keyType {
			case PEM:
				publicKey, err := s.readPublicPEMKeyFromBytes(base64DecodedKey)
				if err != nil {
					return nil, false, err
				}
				publicKeys = append(publicKeys, publicKey)
			case DER:
				publicKey, err := s.readPublicDERKeyFromBytes(base64DecodedKey)
				if err != nil {
					return nil, false, err
				}
				publicKeys = append(publicKeys, publicKey)
			default:
				s.logger.Error("Неизвестный тип ключа")
				return nil, false, ErrInvalidKeyType
			}
		}
	}

	for _, publicKey := range publicKeys {
		// проверка токена
		tok, err := jwt.Parse(strings.ReplaceAll(tokenStr, "Bearer ", ""), func(jwtToken *jwt.Token) (interface{}, error) {
			switch publicKey.(type) {
			case *rsa.PublicKey:
				switch jwtToken.Method.(type) {
				case *jwt.SigningMethodRSA:
					s.logger.Info("SigningMethodRSA")
				case *jwt.SigningMethodHMAC:
					s.logger.Info("SigningMethodHMAC")
				default:
					return nil, fmt.Errorf("unexpected key type: %s, method:%s", jwtToken.Header["alg"], jwtToken.Method)
				}
			case ed25519.PublicKey:
				if _, ok := jwtToken.Method.(*jwt.SigningMethodEd25519); !ok {
					return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
				}
			default:
				s.logger.Error("Неизвестный тип открытого ключа")
				return "", fmt.Errorf("неизвестный тип открытого ключа")
			}

			return publicKey, nil
		},
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithIssuer(s.config.GetString("jwt.issuer")),
			jwt.WithAudience(s.config.GetString("jwt.audience")),
		)

		if err != nil {
			s.logger.Error("jwt token parsing error, ", err.Error())
			continue
		}

		if tok == nil || tok.Claims == nil {
			s.logger.Error("jwt token parsing error")
			return nil, false, errors.New("jwt token parsing error")
		}

		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			return nil, false, fmt.Errorf("invalid token, claims parse error: %w", err)
		}

		return claims, true, nil
	}

	return nil, false, fmt.Errorf("token verification error")
}

func (s *JwtService) readPrivatePEMKey(path string) (crypto.PrivateKey, error) {
	// Читаем приватный ключ
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		s.logger.Error("Ошибка чтения приватного ключа, ", err)
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(err)
	}

	var privateKey crypto.PrivateKey
	privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		s.logger.Warn("Ошибка парсинга приватного ключа, ", err)
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			s.logger.Error("Ошибка парсинга приватного ключа, ", err)
			return nil, err
		}
		return privateKey, err
	}
	return privateKey, nil
}

func (s *JwtService) readPrivatePEMKeyFromBytes(keyBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	var privateKey crypto.PrivateKey
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		s.logger.Warn("Ошибка парсинга приватного ключа, ", err)
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			s.logger.Error("Ошибка парсинга приватного ключа, ", err)
			return nil, err
		}
		return privateKey, err
	}
	return privateKey, nil
}

func (s *JwtService) readPublicPEMKey(path string) (crypto.PublicKey, error) {
	// Читаем открытый ключ
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		s.logger.Error("Ошибка чтения открытого ключа, ", err)
		return nil, ErrInvalidKeyType
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		s.logger.Error("Ошибка парсинга открытого ключа, ", err)
		return nil, ErrInvalidKeyType
	}

	return publicKey, nil
}

func (s *JwtService) readPublicPEMKeyFromBytes(keyBytes []byte) (crypto.PublicKey, error) {

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		s.logger.Error("Ошибка парсинга открытого ключа, ", err)
		return nil, ErrInvalidKeyType
	}

	return publicKey, nil
}

// DER keys format
// https://www.openssl.org/docs/man1.1.1/man1/pkcs8.html
func (s *JwtService) readPublicDERKey(path string) (crypto.PublicKey, error) {
	// Читаем открытый ключ
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		s.logger.Error("Ошибка чтения открытого ключа, ", err)
		return nil, err
	}

	keyData, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return keyData, nil
}

func (s *JwtService) readPublicDERKeyFromBytes(keyBytes []byte) (crypto.PublicKey, error) {
	keyData, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return keyData, nil
}

func (s *JwtService) readPrivateDERKey(path string) (crypto.PrivateKey, error) {
	// Читаем приватный ключ
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		s.logger.Error("Ошибка чтения приватного ключа, ", err)
		return nil, err
	}
	keyData, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return keyData, nil
}

func (s *JwtService) readPrivateDERKeyFromBytes(keyBytes []byte) (crypto.PrivateKey, error) {
	keyData, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return keyData, nil
}

func GetBase64DecodedKeysFromRedis(rdb *redis.Client) ([][]byte, error) {
	res := make([][]byte, 0)
	keyBytes, err := rdb.LRange(context.Background(), "key:pem", 0, 9).Result()
	if err != nil {
		return nil, err
	}

	for _, str := range keyBytes {
		decodedString, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, err
		}
		res = append(res, decodedString)
	}

	return res, nil
}
