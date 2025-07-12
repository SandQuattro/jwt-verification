package jwtverification

import (
	"encoding/base64"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
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
	service := New(zerolog.DefaultContextLogger, PEM, "test", "test")
	claims, _, err := service.ValidateToken(token, "public.pem", r)
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
	service := New(zerolog.DefaultContextLogger, PEM, "test", "test")
	claims, _, err := service.ValidateToken(token, "public.pem", r)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	assert.NotNil(t, claims)
}

func TestValidateOurValidTokenUsingPEMWithoutRedis(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZHIiOiJzYW5kQHRlc3QucnUiLCJhdWQiOiJzbWFydC1hbmFseXRpY3MiLCJleHAiOjE3MTA3NzY3ODQsImZpbyI6Iklnb3IgUy4iLCJpYXQiOjE3MTA3NzYxODQsImlkIjo1LCJpc3MiOiJzbWFydC1hbmFseXRpY3Mtc3NvIiwicm9sIjoiYWRtaW4iLCJzdWIiOiIiLCJzeXMiOiJkaXJlY3QifQ.flfzdg1TL_RbC6S_IdILi4waXjqJVIy60tfGJGNpLY3oU-dAjmFYsQE-0AiAwAEIEyABUxBOn4UrX2CZ1CacUCDS-2gZwAyEihlf69_E9Yc2slMAmtn6fzl05Q-S16ksry1PIpx7rvwWSop_jYf83XSzYLCkZIGVtnK3k1K33PM1M98BQrb7UhQIQ5GhaXGYcn5XmrPKNqpy9Qk3y-5SsUuLobdT05g7w6OLV2JW49XFh30xRmJZBNEKfg9i2Ei9FyKNvx9P8l09O4BP52RqxH-Dlg6LjWdS5UtZKOa5o6QdU9N5n28X1vNy2K7Pw6Eg2cSC5sMTgDKq_RjF0Lq4sXxfvOdlGNx97evele2ALwBn97eyPPcTEtvNjGWi7vufPoUWi4QAWOk7dglBbktnjmlwdAWYWnnKrNHqKCyJEoPfYZg9hfx9p5CFK-lTKhvVIBeplN-VAPXliIX2zhbG8jvpBMVNSRnVGkwW86pmZjXYu4bQX46wRA8ycYYHlN0o0wFam4J_qET_OJiMKAPyLxmYhWH9dxsKnj6dfrQK7G31YYTJLljRu5nLRj-Ed40YIpq3-DAWUj6vTY9VONUS49NmI4GqYBE5hMFo8UUWVOXrDHfm-7R56mPuSm5OiWi9R35UDawQNqgsXoCgMSV0ferf-bgwFZ04SYKEOkJvB98"
	service := New(zerolog.DefaultContextLogger, PEM, "test", "test")
	claims, _, err := service.ValidateToken(token, "public.pem", nil)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	assert.NotNil(t, claims)
}

func TestValidateOurValidTokenUsingPEM(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZHIiOiJzYW5kQHRlc3QucnUiLCJhdWQiOiJzbWFydC1hbmFseXRpY3MiLCJleHAiOjE3MTA3Nzc2MDksImZpbyI6Iklnb3IgUy4iLCJpYXQiOjE3MTA3NzcwMDksImlkIjo1LCJpc3MiOiJzbWFydC1hbmFseXRpY3Mtc3NvIiwicm9sIjoiYWRtaW4iLCJzdWIiOiIiLCJzeXMiOiJkaXJlY3QifQ.nC2rjR4gcW6S_l1yYZK8_Y6byeUoMQEdV9folvMlQyUY6EtodkQ3mHGc1DDmttFdVXxXLLWfutvKQkJ5NnzPp5blr5gn_LggnukEDA9AaLPddUy1-lXTJshxqf0Nd6vmQBREEdJ7k2gVzCROj4yuDRqL6clS-KJi6PQF_EA5qWujex2Hccs3LV2z_kXz34-zb-iLv9HwSMvmlJr3wPXJ_FhbzAdLevKk68fwVKt8AYRgMllJ_uaJg8sSspEYTaeGCb17KUhh0y0PEJ30_jqVGb2yYLRdDaX3rdM8fjMJGhFIP0e8HhGCNEL7-KoOCZutT7B2sFLIcjh5GLQVExDqIpEQQ2vj5ZOi4szrQSF1ykNtHBOO9RjGmL7MAB6LXzsCnv1aQRBF3ZIJ6Wgee1_Jp95hsIzJ4BcNTg_N7yCEkvkpWhNhVO2d0gKrOcy6fHq0hTunXYFrG5RYAA3eg2rsU0mwwsG5MCUsYm5bOiGw-I5LZlHSjOe9KEjgdHe6NWgHK8hGq53riesDwGKgrnu7gGUyEcH0q5MHF0IFTGUlcYGuBWozLm1mSqpU6QS7DuUS-K6QhtUgf8d7iTrVdgW-pyL_FheWxI-MAcGNvLD1ylXYAko557_jcV3U1DAyi9Yq32MzGLCmYfrPHj0wumj19gfWh89csDW2gURicO6ejAI"
	r := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Адрес сервера Redis.
	})
	service := New(zerolog.DefaultContextLogger, PEM, "test", "test")
	claims, _, err := service.ValidateToken(token, "public.pem", r)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	assert.NotNil(t, claims)
}
