package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
)

// Name is set at compile time based on the git repository
var Name string

// Version is set at compile time with the git version
var Version string

func main() {
	app := cli.NewApp()
	app.Name = Name
	app.Usage = `DCOS OAuth authenticating proxy

		An explicit proxy which transparently handles unauthenticated requests
		by obtaining and injecting auth tokens as needed.
		`
	app.Version = Version
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "port, p",
			Value: 8888,
			Usage: "the port on which to listen",
		},
		cli.StringFlag{
			Name:  "target, t",
			Usage: "The target URL to be proxied",
		},
		cli.StringFlag{
			Name:  "auth-endpoint, a",
			Usage: "The target URL to be proxied",
		},
		cli.StringFlag{
			Name:  "host, H",
			Value: "localhost",
			Usage: "the host address on which to listen",
		},
		cli.StringFlag{
			Name:  "username, u",
			Usage: "proxy authentication user",
		},
		cli.StringFlag{
			Name:  "password, P",
			Usage: "proxy authentication password",
		},
		cli.StringFlag{
			Name:  "password-file, f",
			Usage: "proxy authentication password file",
		},
		cli.StringFlag{
			Name:  "principal-secret, s",
			Usage: "principal secret containing credentials for obtaining auth tokens",
		},
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "whether to output all request/response traffic",
		},
		cli.BoolFlag{
			Name:  "insecure, k",
			Usage: "allow connections to SSL sites without valid certs",
		},
	}

	app.Action = func(c *cli.Context) {
		port := c.Int("port")
		host := c.String("host")
		target := c.String("target")
		authEndpoint := c.String("auth-endpoint")
		username := c.String("username")
		password := c.String("password")
		pwfile := c.String("password-file")
		verbose := c.Bool("verbose")
		secret := c.String("principal-secret")
		insecure := c.Bool("insecure")

		if len(secret) == 0 {
			if len(username) == 0 {
				println("ERROR: 'username' is required when 'principal-secret' not specified\n")
				cli.ShowAppHelp(c)
				os.Exit(1)
			}
			if len(password) == 0 && len(pwfile) == 0 {
				println("ERROR: one of 'password' or 'password-file' is required when 'principal-secret' not specified\n")
				cli.ShowAppHelp(c)
				os.Exit(1)
			}
		}

		if len(target) == 0 {
			println("ERROR: 'target' is required\n")
			cli.ShowAppHelp(c)
			os.Exit(1)
		}

		targetURL, err := url.Parse(target)
		if err != nil {
			println(fmt.Sprintf("ERROR: 'target' %s is invalid: %v\n", target, err))
			cli.ShowAppHelp(c)
			os.Exit(1)
		}

		if len(authEndpoint) == 0 {
			authEndpoint = targetURL.Scheme + "://" + targetURL.Host + "/acs/api/v1/auth/login"
		}

		creds, err := parseCredentials([]byte(secret))
		if verbose {
			log.Infof("Parsed credentials from secret: %#v", creds)
		}

		address := fmt.Sprintf("%s:%d", host, port)
		if verbose {
			log.Infof("Proxying %s on %s", target, address)
		}
		handler := NewAuthenticator(targetURL, authEndpoint, creds, verbose, insecure)

		log.Fatal(http.ListenAndServe(address, handler))
	}
	app.Run(os.Args)
}
