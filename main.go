package main

import (
	"fmt"
	"io/ioutil"
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

func run(args []string) {

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
			Name:  "private-key-file, pk",
			Usage: "file containing private-key used to authenticate (requires 'username')",
		},
		cli.StringFlag{
			Name:  "principal-secret, s",
			Usage: "principal secret containing credentials for obtaining auth tokens",
		},
		cli.StringFlag{
			Name:  "principal-secret-file, sf",
			Usage: "principal secret file containing credentials for obtaining auth tokens",
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
		passwordFile := c.String("password-file")
		privateKeyFile := c.String("private-key-file")
		verbose := c.Bool("verbose")
		secret := c.String("principal-secret")
		secretFile := c.String("principal-secret-file")
		insecure := c.Bool("insecure")

		if !c.GlobalIsSet("principal-secret") && !c.GlobalIsSet("principal-secret-file") {
			if len(username) == 0 {
				println("ERROR: 'username' is required when 'principal-secret(-file)' not specified\n")
				cli.ShowAppHelp(c)
				os.Exit(1)
			}
			if len(password) == 0 && len(passwordFile) == 0 && len(privateKeyFile) == 0 {
				println("ERROR: one of 'password' or 'password-file' or 'privateKeyFile' is required when 'principal-secret(-file)' not specified\n")
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

		var creds *credentials
		if len(secret) > 0 {

			creds, err = fromPrincipalSecret([]byte(secret))
			if err != nil {
				println(fmt.Sprintf("ERROR: 'secret' %s could not be parsed: %v\n", secret, err))
				os.Exit(1)
			}

		} else if len(secretFile) > 0 {

			bytes, err := ioutil.ReadFile(secretFile)
			if err != nil {
				println(fmt.Sprintf("ERROR: 'secretFile' %s could not be read: %v\n", secretFile, err))
				os.Exit(1)
			}

			creds, err = fromPrincipalSecret(bytes)

		} else if len(privateKeyFile) > 0 {

			bytes, err := ioutil.ReadFile(privateKeyFile)
			if err != nil {
				println(fmt.Sprintf("ERROR: 'privateKeyFile' %s could not be read: %v\n", privateKeyFile, err))
				os.Exit(1)
			}

			creds, err = fromPrivateKey(username, bytes)

		} else if len(password) > 0 {

			creds = &credentials{UID: username, Password: password}

		} else if len(passwordFile) > 0 {

			bytes, err := ioutil.ReadFile(passwordFile)
			if err != nil {
				println(fmt.Sprintf("ERROR: 'passwordFile' %s could not be read: %v\n", passwordFile, err))
				os.Exit(1)
			}

			creds = &credentials{UID: username, Password: string(bytes)}
		}

		address := fmt.Sprintf("%s:%d", host, port)
		handler := NewAuthenticator(targetURL, authEndpoint, creds, verbose, insecure)

		if err != nil {
			log.Fatal(err)
		} else if verbose {
			log.Infof("Proxying %s on %s", target, address)
		}
		log.Fatal(http.ListenAndServe(address, handler))
	}
	app.Run(args)
}

func main() {
	run(os.Args)
}
