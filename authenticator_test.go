package main

import (
	"bytes"
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"net/http"
	"net/url"

	"net/http/httptest"
)

func TestAuthenticateRetryWithBody(t *testing.T) {

	pk := genPrivateKey(t)
	creds, _ := fromPrivateKey("random", toPEM(pk))
	b := make([]rune, 64)
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}
	token := string(b)

	authServer := httptest.NewTLSServer(&mockAuthEndpoint{pk: pk, token: token})
	defer authServer.Close()

	targetServer := httptest.NewTLSServer(&mockTarget{expectedAuthZ: "token=" + token})
	defer targetServer.Close()
	targetEndpoint, _ := url.Parse(targetServer.URL)

	proxyServer := httptest.NewServer(NewAuthenticator(targetEndpoint, authServer.URL, creds, true, true))
	defer proxyServer.Close()

	req, _ := http.NewRequest("POST", proxyServer.URL, bytes.NewBufferString(`{"cloud":"butt"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)

	assert.Equal(t, 200, resp.StatusCode, "Request should succeed", resp.Body)
}
