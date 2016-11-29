package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
)

type credentials struct {
	UID        string
	PrivateKey *rsa.PrivateKey
	Password   string
}

func fromPrincipalSecret(secret []byte) (*credentials, error) {
	data := make(map[string]interface{})
	if err := json.Unmarshal(secret, &data); err != nil {
		return nil, err
	}
	uid := data["uid"].(string)
	if pk, ok := data["private_key"]; ok {
		privateKey, _ := parsePrivateKey([]byte(pk.(string)))
		return &credentials{UID: uid, PrivateKey: privateKey}, nil
	} else if password, ok := data["password"]; ok {
		return &credentials{UID: uid, Password: password.(string)}, nil
	}
	return nil, nil
}

func fromPrivateKey(username string, pkBytes []byte) (*credentials, error) {
	pk, err := parsePrivateKey(pkBytes)
	if err != nil {
		return nil, err
	}
	return &credentials{UID: username, PrivateKey: pk}, nil
}

func parsePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	var err error
	var block *pem.Block

	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("Failed to parse PEM private key")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pk *rsa.PrivateKey
	var ok bool
	if pk, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, errors.New("Failed to parse PEM private key")
	}

	return pk, nil
}
