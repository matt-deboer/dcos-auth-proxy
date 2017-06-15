package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/prometheus/common/log"
)

type enterpriseStrategy struct {
	Target  *url.URL
	Verbose bool
	client  *http.Client
	creds   *authContext
	hash    crypto.Hash
	// authZ   string
}

func (e *enterpriseStrategy) authenticate() (string, error) {

	var body string
	var bodyLog string
	if e.creds.PrivateKey != nil {
		token, _ := e.getSelfSignedToken()
		body = fmt.Sprintf(`{"uid":"%s","token":"%s"}`, e.creds.UID, token)
		bodyLog = body
	} else {
		body = fmt.Sprintf(`{"uid":"%s","password":"%s"}`, e.creds.UID, e.creds.Password)
		bodyLog = fmt.Sprintf(`{"uid":"%s","password":"%s"}`, e.creds.UID, "****")
	}

	if e.Verbose {
		log.Infof("Authenticating: POST %s  %s", e.creds.AuthEndpoint, bodyLog)
	}

	r, _ := http.NewRequest("POST", e.creds.AuthEndpoint, bytes.NewBufferString(body))
	r.Header.Add("Content-Type", "application/json")
	resp, err := e.client.Do(r)
	checkError(err)

	if e.Verbose {
		log.Infof("Authentication result: %d", resp.StatusCode)
	}

	rbody := []byte{}
	if resp.Body != nil {
		rbodyString, err := ioutil.ReadAll(resp.Body)
		checkError(err)
		rbody = rbodyString
		defer resp.Body.Close()
	}

	if resp.StatusCode == 200 {
		data := make(map[string]interface{})
		if err := json.Unmarshal(rbody, &data); err != nil {
			return "", err
		}
		return data["token"].(string), nil
	}

	log.Error(fmt.Sprintf("POST %s : %d\n%s",
		e.creds.AuthEndpoint, resp.StatusCode, resp.Body))
	return "", errors.New("Failed to authenticate")

}

func (e *enterpriseStrategy) getSelfSignedToken() (string, error) {

	head := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body := base64URLEncode([]byte(fmt.Sprintf(`{"uid": "%s"}`, e.creds.UID)))
	rawToken := head + "." + body

	hashed := sha256.Sum256([]byte(rawToken))
	sig, err := rsa.SignPKCS1v15(rand.Reader, e.creds.PrivateKey, e.hash, hashed[:])
	if err != nil {
		return "", err
	}

	signature := base64URLEncode(sig)
	return rawToken + "." + signature, nil
}
