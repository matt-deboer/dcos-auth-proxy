package main

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	log "github.com/Sirupsen/logrus"
)

type ossStrategy struct {
	Target  *url.URL
	Verbose bool
	client  *http.Client
	creds   *authContext
	hash    crypto.Hash
}

func (o *ossStrategy) authenticate() (string, error) {

	idToken, err := o.getIDToken()
	if err != nil {
		return "", err
	}

	body := fmt.Sprintf(`{"token":"%s"}`, idToken)
	bodyLog := fmt.Sprintf(`{"token":"*****"}`)

	if o.Verbose {
		log.Infof("Authenticating: POST %s  %s", o.creds.AuthEndpoint, bodyLog)
	}

	r, _ := http.NewRequest("POST", o.creds.AuthEndpoint, bytes.NewBufferString(body))
	r.Header.Add("Content-Type", "application/json")
	resp, err := o.client.Do(r)
	checkError(err)

	if o.Verbose {
		log.Infof("Authentication result: %d", resp.StatusCode)
	}

	rbody := []byte{}
	if resp.Body != nil {
		rbodyString, err := ioutil.ReadAll(resp.Body)
		checkError(err)
		rbody = rbodyString
		defer resp.Body.Close()
	}

	var token string
	if resp.StatusCode == 200 {
		data := make(map[string]interface{})
		if err := json.Unmarshal(rbody, &data); err != nil {
			return "", err
		}
		if _token, ok := data["token"]; ok {
			token = _token.(string)
		}
	}

	if len(token) == 0 {
		log.Error(fmt.Sprintf("POST %s : %d\n%s",
			o.creds.AuthEndpoint, resp.StatusCode, resp.Body))
		return "", errors.New("Failed to obtain DC/OS AuthN token")
	}

	return token, nil
}

func (o *ossStrategy) getIDToken() (string, error) {

	body := fmt.Sprintf(`{"grant_type":"password","scope":"openid email",
		"client_id":"%s","client_secret":"%s","username":"%s","password":"%s"}`,
		o.creds.OAuthClientID, o.creds.OAuthClientSecret, o.creds.UID, o.creds.Password)

	bodyLog := fmt.Sprintf(`{"grant_type":"password","scope":"openid email",
		"client_id":"%s","client_secret":"%s","username":"%s","password":"*****"}`,
		o.creds.OAuthClientID, o.creds.OAuthClientSecret, o.creds.UID)

	if o.Verbose {
		log.Infof("Authenticating: POST %s  %s", o.creds.TokenEndpoint, bodyLog)
	}

	r, _ := http.NewRequest("POST", o.creds.TokenEndpoint, bytes.NewBufferString(body))
	r.Header.Add("Content-Type", "application/json")
	resp, err := o.client.Do(r)
	checkError(err)

	if o.Verbose {
		log.Infof("Authentication result: %d", resp.StatusCode)
	}

	rbody := []byte{}
	if resp.Body != nil {
		rbodyString, err := ioutil.ReadAll(resp.Body)
		checkError(err)
		rbody = rbodyString
		defer resp.Body.Close()
	}

	var idToken string
	if resp.StatusCode == 200 {
		data := make(map[string]interface{})
		if err := json.Unmarshal(rbody, &data); err != nil {
			return "", err
		}
		if _idToken, ok := data["id_token"]; ok {
			idToken = _idToken.(string)
		}
	}

	if len(idToken) == 0 {
		log.Error(fmt.Sprintf("POST %s : %d\n%s",
			o.creds.TokenEndpoint, resp.StatusCode, resp.Body))
		return "", errors.New("Failed to obtain OIDC id_token")
	}

	return idToken, nil
}
