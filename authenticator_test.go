package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"net/http"
	"net/url"

	"encoding/json"
	"io/ioutil"
	"net/http/httptest"
)

func genPrivateKey(t *testing.T) *rsa.PrivateKey {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	testError(t, err)
	return pk
}

func toPEM(pk *rsa.PrivateKey) []byte {
	var buffer bytes.Buffer
	pem.Encode(&buffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
	return buffer.Bytes()
}

type mockAuthEndpoint struct {
	pk    *rsa.PrivateKey
	token string
}

func (m *mockAuthEndpoint) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	bytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}
	data := make(map[string]interface{})
	err = json.Unmarshal(bytes, &data)
	if err != nil {
		panic(err)
	}
	// TODO: verify the token
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"token":"` + m.token + `"}`))
}

type mockTarget struct {
	expectedAuthZ string
}

func (m *mockTarget) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	authZ := req.Header.Get("Authorization")
	if authZ == m.expectedAuthZ {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	} else {
		w.WriteHeader(401)
		w.Write([]byte("Unauthorized"))
	}
}

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
