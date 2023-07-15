package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/k0kubun/pp/v3"
	"github.com/romnn/flags4urfavecli/flags"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Rev is set on build time to the git HEAD
var Rev = ""

// Version is incremented using bump2version
const Version = "0.1.1"

func main() {
	app := &cli.App{
		Version:   Version,
		Usage:     "Create client certs, CSRs etc and get them signed by RASENMAEHER using the info from KRAFTWERK provided manifest file",
		Name:      "kw_product_init",
		ArgsUsage: "/path/to/manifest.json",
		Flags: []cli.Flag{
			&flags.LogLevelFlag,
			&cli.StringFlag{
				Name:  "capath",
				Usage: "Path to CA certificates (directory)",
				Value: "/ca_public",
			},
			&cli.StringFlag{
				Name:  "datapath",
				Usage: "Base path for saving things",
				Value: "/data/persistent",
			},
			&cli.IntFlag{
				Name:  "keybits",
				Usage: "How many bits to private key",
				Value: 4096,
			},
			&cli.BoolFlag{
				Name:  "insecure",
				Usage: "Do not verify RASENMAEHER server certificate",
				Value: false,
			},
		},
		Action: func(ctx *cli.Context) error {
			if level, err := log.ParseLevel(ctx.String("log")); err == nil {
				log.SetLevel(level)
			}
			if ctx.Args().Len() < 1 {
				log.Fatal("No manifest path given")
				cli.ShowAppHelpAndExit(ctx, 1)
			}

			jfile, err := os.ReadFile(ctx.Args().Get(0))
			if err != nil {
				log.Fatal(err)
				return cli.Exit("Cannot open manifest file", 1)
			}
			var payload map[string]interface{}
			err = json.Unmarshal(jfile, &payload)
			if err != nil {
				log.Fatal(err)
				return cli.Exit("Cannot parse JSON file", 1)
			}
			log.Debug("payload: ", pp.Sprint(payload))

			rmPayload, ok := payload["rasenmaeher"]
			if !ok {
				msg := "No key for RASENMAEHER info in manifest"
				log.Fatal(msg)
				return cli.Exit(msg, 1)
			}
			log.Debug("rmPayload: ", pp.Sprint(rmPayload))
			productPayload, ok := payload["product"]
			if !ok {
				msg := "No key for product info in manifest"
				log.Fatal(msg)
				return cli.Exit(msg, 1)
			}
			log.Debug("productPayload: ", pp.Sprint(productPayload))

			certpool, err := readCAs(ctx.String("capath"))
			if err != nil {
				log.Fatal(err)
				return cli.Exit("Could not load CAs", 1)
			}
			log.Debug("certpool: ", pp.Sprint(certpool))

			keypair, err := createKeyPair(ctx.String("datapath"), ctx.Int("keybits"))
			if err != nil {
				log.Fatal(err)
				return cli.Exit("Could not create keypair", 1)
			}
			log.Debug("keypair: ", pp.Sprint(keypair))

			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func readCAs(capath string) (*x509.CertPool, error) {
	certFiles, err := filepath.Glob(filepath.Join(capath, "*.pem"))
	if err != nil {
		return nil, fmt.Errorf("Failed to scan certificate dir \"%s\": %s", capath, err)
	}
	certpool := x509.NewCertPool()

	sort.Strings(certFiles)
	for _, file := range certFiles {
		log.Info("Adding ", file)
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for {
			block, rest := pem.Decode(raw)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				certpool.AppendCertsFromPEM(block.Bytes)
			}
			raw = rest
		}
	}

	return certpool, nil
}

func makeDirectoryIfNotExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.Mkdir(path, os.ModeDir|0755)
	}
	return nil
}

func createKeyPair(datapath string, keybits int) (*rsa.PrivateKey, error) {
	privdir := path.Join(datapath, "private")
	err := makeDirectoryIfNotExists(privdir)
	if err != nil {
		return nil, err
	}
	pubdir := path.Join(datapath, "public")
	err = makeDirectoryIfNotExists(pubdir)
	if err != nil {
		return nil, err
	}

	log.Info("Generating keypair")
	keypair, err := rsa.GenerateKey(rand.Reader, keybits)
	if err != nil {
		return nil, err
	}

	privKeyPEM := new(bytes.Buffer)
	err = pem.Encode(privKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keypair),
	})
	if err != nil {
		return nil, err
	}
	privkeypath := path.Join(privdir, "mtsclient.key")
	err = os.WriteFile(privkeypath, privKeyPEM.Bytes(), 640)
	if err != nil {
		return nil, err
	}
	log.Info("Wrote ", privkeypath)

	pubKeyPEM := new(bytes.Buffer)
	err = pem.Encode(pubKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&keypair.PublicKey),
	})
	if err != nil {
		return nil, err
	}
	pubkeypath := path.Join(pubdir, "mtsclient.pub")
	err = os.WriteFile(pubkeypath, pubKeyPEM.Bytes(), 644)
	if err != nil {
		return nil, err
	}
	log.Info("Wrote ", pubkeypath)

	return keypair, nil
}
