package main

import (
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli"
)

func TestCLISecret(t *testing.T) {

	pk := genPrivateKey(t)
	token := genToken()

	authServer := httptest.NewTLSServer(&mockAuthEndpoint{pk: pk, token: token})
	defer authServer.Close()

	targetServer := httptest.NewTLSServer(&mockTarget{expectedAuthZ: "token=" + token})
	defer targetServer.Close()

	l, err := net.Listen("tcp", "localhost:0")
	assert.NoError(t, err)
	port := strings.Split(l.Addr().String(), ":")[1]
	l.Close()

	args := []string{
		"dcos-auth-proxy",
		"-t", targetServer.URL,
		"-p", port,
		"-s", `{"login_endpoint":"` + authServer.URL + `","uid":"random","private_key":"` + strings.Replace(string(toPEM(pk)), "\n", "\\n", -1) + `"}`,
		"-k", "-V",
	}

	go run(args, os.Stdin, os.Stderr)

	req, _ := http.NewRequest("POST", "http://localhost:"+port, bytes.NewBufferString(`{"cloud":"butt"}`))
	req.Header.Set("Content-Type", "application/json")
	println("req.URL:" + req.URL.String())

	resp, err := http.DefaultClient.Do(req)
	start := time.Now()
	for err != nil && strings.Contains(err.Error(), "connection refused") && time.Since(start) < time.Minute {
		time.Sleep(100 * time.Millisecond)
		resp, err = http.DefaultClient.Do(req)
	}
	assert.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode, "Request should succeed", resp.Body)
}

func TestCLIUsernamePassword(t *testing.T) {

	pk := genPrivateKey(t)
	token := genToken()

	authServer := httptest.NewTLSServer(&mockAuthEndpoint{pk: pk, token: token})
	defer authServer.Close()

	targetServer := httptest.NewTLSServer(&mockTarget{expectedAuthZ: "token=" + token})
	defer targetServer.Close()

	l, err := net.Listen("tcp", "localhost:0")
	assert.NoError(t, err)
	port := strings.Split(l.Addr().String(), ":")[1]
	l.Close()

	args := []string{
		"dcos-auth-proxy",
		"-t", targetServer.URL,
		"-a", authServer.URL,
		"-p", port,
		"-u", "random",
		"-P", "T0P53cr3t!",
		"-k", "-V",
	}
	go run(args, os.Stdin, os.Stderr)

	req, _ := http.NewRequest("POST", "http://localhost:"+port, bytes.NewBufferString(`{"cloud":"butt"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	start := time.Now()
	for err != nil && strings.Contains(err.Error(), "connection refused") && time.Since(start) < time.Minute {
		time.Sleep(100 * time.Millisecond)
		resp, err = http.DefaultClient.Do(req)
	}
	assert.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode, "Request should succeed", resp.Body)
}

func TestCLIAuthenticate(t *testing.T) {

	pk := genPrivateKey(t)
	token := genToken()

	authServer := httptest.NewTLSServer(&mockAuthEndpoint{pk: pk, token: token})
	defer authServer.Close()

	targetServer := httptest.NewTLSServer(&mockTarget{expectedAuthZ: "token=" + token})
	defer targetServer.Close()

	args := []string{
		"dcos-auth-proxy",
		"authenticate",
		"-a", authServer.URL,
		"-u", "random",
		"-P", "T0P53cr3t!",
		"-k", "-V",
	}
	r, w, _ := os.Pipe()

	run(args, w, os.Stderr)

	w.Close()
	bytes, err := ioutil.ReadAll(r)
	assert.NoError(t, err)

	assert.NotEmpty(t, string(bytes))
}

func TestCLIParseFlags(t *testing.T) {

	pk := genPrivateKey(t)
	token := genToken()

	authServer := httptest.NewTLSServer(&mockAuthEndpoint{pk: pk, token: token})
	defer authServer.Close()

	targetServer := httptest.NewTLSServer(&mockTarget{expectedAuthZ: "token=" + token})
	defer targetServer.Close()

	results := make(chan map[string]interface{}, 1)
	app := cli.NewApp()
	app.Commands = []cli.Command{
		cli.Command{
			Name:  "authenticate",
			Flags: commonFlags,
			Action: func(c *cli.Context) {
				creds, targetURL := parseFlags(c)
				results <- map[string]interface{}{
					"creds":     creds,
					"targetURL": targetURL,
				}
			},
		},
	}
	err := app.Run([]string{
		"dcos-auth-proxy",
		"authenticate",
		"-a", "http://some-other-url",
		"-s", `{"login_endpoint":"` + authServer.URL + `","uid":"random","private_key":"` + strings.Replace(string(toPEM(pk)), "\n", "\\n", -1) + `"}`,
		"-k",
		"-V",
	})
	if !assert.NoError(t, err, "Command should parse flags successfully") {
		t.Fatal(err)
	}

	result := <-results
	if result["creds"].(*authContext).AuthEndpoint != "http://some-other-url" {
		t.Error("Auth endpoint should be overridden")
	}
}
