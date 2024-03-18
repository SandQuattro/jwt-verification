package jwtverification

import (
	"encoding/base64"
	"github.com/gurkankaymak/hocon"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateBase64FromKey(t *testing.T) {
	token := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6UcbybuH2YlNw6PEtOUg
Im7Pkmg6oBlSUeloM8rXqLAB+gStohRMa92RmQ+ZCBUTG7t6PZprS9/77NOept73
50qEr7wdeR9/gcjP27wrM+vW+XpWg8mIHPVBzuAJfKU9buSuJCjHeEPhEGrYhj6U
WAXdkAz5Ao9V4U+E1tmT8kI2tf2l8SLH03oceh3uzPdJZkpsZ47ornKWDFwxu8Td
2t+1yarVT7CfMABFuFtapagSGLA5ETY5/kq5rjuNzVJcLl+/2nR3wnwRQcYPS/YZ
OlxjFH5I9/wzYZL22S4BcMjZpOnvQLZ/eloYaPtEXgX3wEf11Oq2Nk0z29CDxuul
GwIDAQAB
-----END PUBLIC KEY-----`
	baseKey := make([]byte, base64.StdEncoding.EncodedLen(len(token)))
	base64.StdEncoding.Encode(baseKey, []byte(token))
	t.Logf("%s", baseKey)
}

func TestValidateInvalidTokenUsingPEM(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	r := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Адрес сервера Redis.
	})
	service := New(&hocon.Config{}, logrus.New(), PEM)
	claims, _, err := service.ValidateToken(token, "", r)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	assert.NotNil(t, claims)
}

func TestValidateExternalSystemValidTokenUsingPEM(t *testing.T) {
	token := "eyJ4NXQiOiJNell4TW1Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUXpOR00wWkdSbE5qSmtPREZrWkRSaU9URmtNV0ZoTXpVMlpHVmxOZyIsImtpZCI6Ik16WXhNbUZrT0dZd01XSTBaV05tTkRjeE5HWXdZbU00WlRBM01XSTJOREF6WkdRek5HTTBaR1JsTmpKa09ERmtaRFJpT1RGa01XRmhNelUyWkdWbE5nX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJtYXBpYyIsImF1dCI6IkFQUExJQ0FUSU9OIiwiYXVkIjoiUjJJZm1sWXEzdWFOMFFjaGNjWU9HemloRE4wYSIsIm5iZiI6MTcxMDM5MzI1NSwiYXpwIjoiUjJJZm1sWXEzdWFOMFFjaGNjWU9HemloRE4wYSIsInNjb3BlIjoiZGVmYXVsdCIsImlzcyI6Imh0dHBzOlwvXC9zdGFnZS5hcHBzLm1uLWtwMDEudmltcGVsY29tLnJ1OjQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTcxMDQ3OTY1NSwiaWF0IjoxNzEwMzkzMjU1LCJqdGkiOiJkYzQxNDU3ZC1jMmEwLTQxOTQtOTUxMi1hNGJkMDYxYTMyMWYifQ.gzNtYqtnm0ayQxJuZ4dDARWu7P1eB8Ka7SbwSu1nvXMQXsj5B6eNHf_WYirT0rMwslPgca5w-_WSGue3BzRo70uSTpoonuhIvlgW-3qGTKs3ilfU828rzkWiQsWRBf06Y7LtG6D4QR3ztVQYFn2j_9NE9ZQclSPmsXgUzxG5ON1eo2diOrgtmX5_ie49eopUjjdvEM8JPszMF4sU_6-rUcWRghIDFcSJxoyvP1ACQxaJSRo8M3LECa_JZqB5L4Z7jrOLz6ysZ8oM6pwZuLnKBOxKCiM-5vsDQka0TT2l84wB3-HbjGomVhcYqtPKG8sstZ-f0VpZ-o9Ssae3_MiFnQ"
	r := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Адрес сервера Redis.
	})
	service := New(&hocon.Config{}, logrus.New(), PEM)
	claims, _, err := service.ValidateToken(token, "", r)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	assert.NotNil(t, claims)
}

func TestValidateOurValidTokenUsingPEMWithoutRedis(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZHIiOiJzYW5kQHRlc3QucnUiLCJhdWQiOiJzbWFydC1hbmFseXRpY3MiLCJleHAiOjE3MTAzNDQwMTQsImZpbyI6Iklnb3IgUy4iLCJpYXQiOjE3MTAzNDM5NTQsImlkIjo1LCJpc3MiOiJzbWFydC1hbmFseXRpY3Mtc3NvIiwicm9sIjoiYWRtaW4iLCJzdWIiOiIiLCJzeXMiOiJkaXJlY3QifQ.Fk-DfT6Kwr1sfjomtt8pfTA8JVla9xwUYN7UW-6sOlIlkvLmTT3Pdtrkg8TpuqPyxc_3_zgj6Z3MFd2ZXVna0rNt-4vSLq6MWQUDLHWXJoS_zaj68CT-dJI9V41Nb1elWEJ2ocRwXCbd4cjSAhWJY6-383PSg4pZH9NtXXQV3dhFbbRKSq4gYBGhtrt1EwBXJ_VLvdhFe3tAwziwGZyuK06hWYmMjq_msZlS3Gg3MeHdHdQsdgi6nZf_YaCutxXa0vPmJKSQcN9luvB9tOGycEygCOWc0HBQYpmFAbHxh8jkvD0XViGxb8pQP7kubYp_lt8uil9f_W4HPtvaxu4lRA"
	service := New(&hocon.Config{}, logrus.New(), PEM)
	claims, _, err := service.ValidateToken(token, "public.pem", nil)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	assert.NotNil(t, claims)
}

func TestValidateOurValidTokenUsingPEM(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZHIiOiJzYW5kQHRlc3QucnUiLCJhdWQiOiJzbWFydC1hbmFseXRpY3MiLCJleHAiOjE3MTAzNDQwMTQsImZpbyI6Iklnb3IgUy4iLCJpYXQiOjE3MTAzNDM5NTQsImlkIjo1LCJpc3MiOiJzbWFydC1hbmFseXRpY3Mtc3NvIiwicm9sIjoiYWRtaW4iLCJzdWIiOiIiLCJzeXMiOiJkaXJlY3QifQ.Fk-DfT6Kwr1sfjomtt8pfTA8JVla9xwUYN7UW-6sOlIlkvLmTT3Pdtrkg8TpuqPyxc_3_zgj6Z3MFd2ZXVna0rNt-4vSLq6MWQUDLHWXJoS_zaj68CT-dJI9V41Nb1elWEJ2ocRwXCbd4cjSAhWJY6-383PSg4pZH9NtXXQV3dhFbbRKSq4gYBGhtrt1EwBXJ_VLvdhFe3tAwziwGZyuK06hWYmMjq_msZlS3Gg3MeHdHdQsdgi6nZf_YaCutxXa0vPmJKSQcN9luvB9tOGycEygCOWc0HBQYpmFAbHxh8jkvD0XViGxb8pQP7kubYp_lt8uil9f_W4HPtvaxu4lRA"
	r := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Адрес сервера Redis.
	})
	service := New(&hocon.Config{}, logrus.New(), PEM)
	claims, _, err := service.ValidateToken(token, "public.pem", r)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	assert.NotNil(t, claims)
}
