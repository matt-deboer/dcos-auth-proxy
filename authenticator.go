package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/base64"
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
	Target   *url.URL
	Verbose  bool
	client   *http.Client
	authZ    string
	strategy strategy
}

type strategy interface {
	authenticate() (string, error)
}

func base64URLEncode(bytes []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(bytes), "=")
}

func newAuthenticator(target *url.URL, creds *authContext, verbose bool, insecure bool) *authenticator {
	var client *http.Client
	if insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	} else {
		client = &http.Client{}
	}

	var strategy strategy
	if len(creds.TokenEndpoint) > 0 {
		strategy = &auth0Strategy{client: client, creds: creds, Verbose: verbose}
	} else {
		strategy = &enterpriseStrategy{client: client, creds: creds, Verbose: verbose, hash: crypto.SHA256}
	}

	return &authenticator{Target: target, strategy: strategy, Verbose: verbose, client: client}
}

// NewAuthenticationHandler creates a new *goproxy.ProxyHttpServer with an automatic
// authentication handler using the authContext provided. URLs are re-written
// to point at the provided 'target'.
func NewAuthenticationHandler(target *url.URL, creds *authContext, verbose bool, insecure bool) *goproxy.ProxyHttpServer {

	a := newAuthenticator(target, creds, verbose, insecure)

	proxy := goproxy.NewProxyHttpServer()
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
					authZ, err := a.strategy.authenticate()
					if err != nil {
						log.Errorf("Authentication failure: %v", err)
						response = r
					} else {
						a.authZ = "token=" + authZ
						ctx.Req.Header.Set("Authorization", a.authZ)
						ctx.Req.Body = ioutil.NopCloser(bytes.NewBuffer(ctx.UserData.([]byte)))
						response, _ = a.client.Do(ctx.Req)
					}
				} else {
					response = r
				}
			}
			if strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") {
				if a.Verbose {
					log.Info("Adding eventStreamBody wrapper")
				}
				response.Body = newEventStreamBody(response.Body)
			}
			return response
		})

	proxy.Tr.Proxy = nil
	return proxy
}
