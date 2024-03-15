package jwtverification

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/gurkankaymak/hocon"
	"github.com/labstack/echo-contrib/jaegertracing"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"os"
	"strings"
	"time"
)

var ErrInvalidKeyType = errors.New("invalid key type")
var ErrInvalidToken = errors.New("invalid token")

type Keys int

const (
	PEM = iota
	DER
)

type JwtService struct {
	config *hocon.Config
	logger *logrus.Logger
	keys   Keys
}

func New(config *hocon.Config, logger *logrus.Logger, keys Keys) *JwtService {
	return &JwtService{config: config, logger: logger, keys: keys}
}

func (s *JwtService) RefreshJwtToken(ctx echo.Context, tokenStr string) (string, error) {
	span := jaegertracing.CreateChildSpan(ctx, "refresh jwt token")
	defer span.Finish()

	// проверка токена
	claims, isValid, err := s.ValidateToken(tokenStr)
	if err != nil {
		return "", err
	}
	if !isValid {
		return "", ErrInvalidToken
	}

	span.SetTag("userID", claims["id"].(int))

	token, err := s.recreateJwtTokenWithClaims(claims)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *JwtService) JwtClaims(tokenStr string) (jwt.MapClaims, error) {
	claims, isValid, err := s.ValidateToken(tokenStr)
	if !isValid {
		s.logger.Error("JwtClaims getting failed")
		return nil, err
	}
	return claims, nil
}

func (s *JwtService) ValidateToken(tokenStr string) (jwt.MapClaims, bool, error) {
	var err error
	var publicKey crypto.PublicKey

	if s.keys == PEM {
		publicKey, err = s.readPublicPEMKey(s.config.GetString("jwt.pem.public"))
	} else {
		publicKey, err = s.readPublicDERKey(s.config.GetString("jwt.der.public"))
	}

	// проверка токена
	tok, err := jwt.Parse(strings.ReplaceAll(tokenStr, "Bearer ", ""), func(jwtToken *jwt.Token) (interface{}, error) {
		switch publicKey.(type) {
		case *rsa.PublicKey:
			if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
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
	})
	if err != nil {
		s.logger.Error("Ошибка парсинга jwt токена, ", err)
		return nil, false, err
	}

	if tok == nil || tok.Claims == nil {
		s.logger.Error("Ошибка парсинга jwt токена")
		return nil, false, errors.New("ошибка парсинга jwt токена")
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false, fmt.Errorf("invalid token, claims parse error: %w", err)
	}

	if !claims.VerifyIssuer(s.config.GetString("jwt.issuer"), true) {
		return nil, false, fmt.Errorf("token issuer error")
	}

	if !claims.VerifyAudience(s.config.GetString("jwt.audience"), true) {
		return nil, false, fmt.Errorf("token audience error")
	}

	return claims, true, nil
}

func (s *JwtService) recreateJwtTokenWithClaims(claims jwt.MapClaims) (string, error) {
	var err error
	var privateKey crypto.PublicKey

	if s.keys == PEM {
		privateKey, err = s.readPrivatePEMKey(s.config.GetString("jwt.pem.private"))
	} else {
		privateKey, err = s.readPrivateDERKey(s.config.GetString("jwt.der.private"))
	}

	if err != nil {
		return "", err
	}

	// Меняем даты выдачи и expire
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(s.config.GetInt("jwt.expiredAfterMinutes"))).Unix()

	// Генерируем токен
	token, err := jwt.NewWithClaims(getSigningMethod(privateKey), claims).SignedString(privateKey)
	if err != nil {
		s.logger.Error("Ошибка генерации jwt токена, ", err)
		return "", err
	}

	return token, nil
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

func getSigningMethod(privateKey any) jwt.SigningMethod {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA
	default:
		return nil
	}
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
