package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePrivateKeyFile(t *testing.T) {

	pkBytes := toPEM(genPrivateKey(t))

	creds, err := fromPrivateKey("random", pkBytes)
	assert.NoError(t, err)
	assert.NotNil(t, creds, "Creds should be parsed")
	assert.Equal(t, "random", creds.UID, "UID not equal")

}

func TestParsePrincipalSecretFile(t *testing.T) {

	pkBytes := toPEM(genPrivateKey(t))

	_json := make(map[string]interface{})
	_json["uid"] = "random"
	_json["private_key"] = string(pkBytes)
	jsonBytes, _ := json.Marshal(_json)

	creds, err := fromPrincipalSecret(jsonBytes)
	assert.NoError(t, err)
	assert.NotNil(t, creds, "Creds should be parsed")
	assert.Equal(t, "random", creds.UID, "UID not equal")
	assert.NotNil(t, creds.PrivateKey, "Private key should be parsed")
}
