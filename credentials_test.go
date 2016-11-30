package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testError(t *testing.T, err error) {
	if err != nil {
		t.Error(err)
	}
}

func genPrivateKeyPEM(t *testing.T) []byte {

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	testError(t, err)

	var buffer bytes.Buffer
	err = pem.Encode(&buffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})

	return buffer.Bytes()
}

func TestParsePrivateKeyFile(t *testing.T) {

	pkBytes := genPrivateKeyPEM(t)

	creds, err := fromPrivateKey("random", pkBytes)
	assert.NoError(t, err)
	assert.NotNil(t, creds, "Creds should be parsed")
	assert.Equal(t, "random", creds.UID, "UID not equal")

}

func TestParsePrincipalSecretFile(t *testing.T) {

	pkBytes := genPrivateKeyPEM(t)

	_json := make(map[string]interface{})
	_json["uid"] = "random"
	_json["private_key"] = string(pkBytes)
	jsonBytes, err := json.Marshal(_json)
	testError(t, err)

	creds, err := fromPrincipalSecret(jsonBytes)
	assert.NoError(t, err)
	assert.NotNil(t, creds, "Creds should be parsed")
	assert.Equal(t, "random", creds.UID, "UID not equal")
}
