package main

import (
	"encoding/json"
	"os"

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
			&cli.BoolFlag{
				Name:  "insecure",
				Usage: "Do not verify server certificate",
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

			jfile, err := os.ReadFile(ctx.Args().Get(1))
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
			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
