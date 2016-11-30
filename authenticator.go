package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/elazarl/goproxy"
)

// Panic if called for
func checkError(err error) {
	if err != nil {
		log.Error(fmt.Sprintf("Panic on error: %s", err))
		panic(err)
	}
}

type authenticator struct {
	AuthEndpoint string
	Target       *url.URL
	Verbose      bool
	client       *http.Client
	creds        *credentials
	hash         crypto.Hash
	authZ        string
}

func (a *authenticator) authenticate() (string, error) {

	var body string
	var bodyLog string
	if a.creds.PrivateKey != nil {
		token, _ := a.getSelfSignedToken()
		body = fmt.Sprintf(`{"uid":"%s","token":"%s"}`, a.creds.UID, token)
		bodyLog = body
	} else {
		body = fmt.Sprintf(`{"uid":"%s","password":"%s"}`, a.creds.UID, a.creds.Password)
		bodyLog = fmt.Sprintf(`{"uid":"%s","password":"%s"}`, a.creds.UID, "****")
	}

	if a.Verbose {
		log.Infof("Authenticating: POST %s  %s", a.AuthEndpoint, bodyLog)
	}

	r, _ := http.NewRequest("POST", a.AuthEndpoint, bytes.NewBufferString(body))
	r.Header.Add("Content-Type", "application/json")
	resp, err := a.client.Do(r)
	checkError(err)

	if a.Verbose {
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
		return "token=" + data["token"].(string), nil
	}

	log.Error(fmt.Sprintf("POST %s : %d\n%s",
		a.AuthEndpoint, resp.StatusCode, resp.Body))
	return "", errors.New("Failed to authenticate")

}

func (a *authenticator) getSelfSignedToken() (string, error) {

	head := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body := base64URLEncode([]byte(fmt.Sprintf(`{"uid": "%s"}`, a.creds.UID)))
	rawToken := head + "." + body

	hashed := sha256.Sum256([]byte(rawToken))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.creds.PrivateKey, a.hash, hashed[:])
	if err != nil {
		return "", err
	}

	signature := base64URLEncode(sig)
	return rawToken + "." + signature, nil
}

func base64URLEncode(bytes []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(bytes), "=")
}

// NewAuthenticator creates a new *goproxy.ProxyHttpServer with an automatic
// authentication handler using the credentials provided. URLs are re-written
// to point at the provided 'target'.
func NewAuthenticator(target *url.URL, authEndpoint string, creds *credentials, verbose bool, insecure bool) *goproxy.ProxyHttpServer {

	a := &authenticator{Target: target, AuthEndpoint: authEndpoint, creds: creds, Verbose: verbose, hash: crypto.SHA256}

	proxy := goproxy.NewProxyHttpServer()
	if insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		a.client = &http.Client{Transport: tr}
	} else {
		a.client = &http.Client{}
	}

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if a.Verbose {
			log.Debug(fmt.Sprintf("Handling Non-Proxy request for: %s", req.URL.String()))
		}
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})

	proxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			originalURL := req.URL.String()
			req.URL.Host = target.Host
			req.URL.Scheme = target.Scheme
			if len(target.Path) > 0 {
				req.URL.Path = target.Path + req.URL.Path
			}
			if a.Verbose {
				log.Infof("Proxying %s --> %s", originalURL, req.URL.String())
			}
			req.Header.Set("Authorization", a.authZ)
			reqBody, err := ioutil.ReadAll(req.Body)
			if err != nil {
				log.Errorf("Error reading request body: %v", err)
				resp, _ := http.ReadResponse(bufio.NewReader(bytes.NewBufferString("Error reading request body")), req)
				return req, resp
			}
			req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))
			ctx.UserData = reqBody
			return req, nil
		})

	proxy.OnResponse().DoFunc(
		func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if a.Verbose {
				if r != nil {
					log.Info(fmt.Sprintf("Handling %d response for %v", r.StatusCode, ctx.Req.URL))
				} else {
					log.Warning("Response is nil!")
				}
			}
			var response *http.Response
			if r != nil {
				if r.StatusCode == 401 {
					authZ, err := a.authenticate()
					if err != nil {
						log.Errorf("Authentication failure: %v", err)
						response = r
					} else {
						a.authZ = authZ
						ctx.Req.Header.Set("Authorization", a.authZ)
						ctx.Req.Body = ioutil.NopCloser(bytes.NewBuffer(ctx.UserData.([]byte)))
						response, _ = a.client.Do(ctx.Req)
					}
				} else {
					response = r
				}
			}
			return response
		})

	proxy.Tr.Proxy = nil
	return proxy
}
