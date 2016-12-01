package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"net/http"
	"net/url"

	"net/http/httptest"
)

func TestAuthenticateRetryWithBody(t *testing.T) {

	token := genToken()
	pk := genPrivateKey(t)

	authServer := httptest.NewTLSServer(&mockAuthEndpoint{pk: pk, token: token})
	defer authServer.Close()

	targetServer := httptest.NewTLSServer(&mockTarget{expectedAuthZ: "token=" + token})
	defer targetServer.Close()
	targetEndpoint, _ := url.Parse(targetServer.URL)

	creds, _ := fromPrivateKey("random", toPEM(pk), authServer.URL)
	proxyServer := httptest.NewServer(NewAuthenticationHandler(targetEndpoint, creds, true, true))
	defer proxyServer.Close()

	req, _ := http.NewRequest("POST", proxyServer.URL, bytes.NewBufferString(`{"cloud":"butt"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)

	assert.Equal(t, 200, resp.StatusCode, "Request should succeed", resp.Body)
}

func TestAuthenticate(t *testing.T) {

	pk := genPrivateKey(t)
	token := genToken()

	authServer := httptest.NewTLSServer(&mockAuthEndpoint{pk: pk, token: token})
	defer authServer.Close()

	targetServer := httptest.NewTLSServer(&mockTarget{expectedAuthZ: "token=" + token})
	defer targetServer.Close()
	targetEndpoint, _ := url.Parse(targetServer.URL)

	creds, _ := fromPrivateKey("random", toPEM(pk), authServer.URL)
	a := newAuthenticator(targetEndpoint, creds, true, true)

	token, err := a.authenticate()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}
