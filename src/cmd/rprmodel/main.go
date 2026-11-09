// Command rprmodel evaluates fixtures and the fixed sweep with the
// ReplacePathRegex model.
//
//	rprmodel results <cases.tsv> <outdir>   write cases.tsv and sweep.csv
//	rprmodel case pre|post <target> <regex> <replacement>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/federiconbaez/cortex9-traefik-replacepathregex-normalization-model/src/model"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "rprmodel:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 5 && args[0] == "case" {
		o := model.Run(model.Case{ID: "cli", Target: args[2], Regex: args[3], Replacement: args[4], Mode: model.ModeRouter}, args[1])
		fmt.Println(model.Header)
		fmt.Println(o.Row())
		return nil
	}
	if len(args) != 3 || args[0] != "results" {
		return fmt.Errorf("usage: rprmodel results <cases.tsv> <outdir> | case pre|post <target> <regex> <replacement>")
	}
	cases, err := model.LoadCases(args[1])
	if err != nil {
		return err
	}
	if err := os.MkdirAll(args[2], 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString(model.Header + "\n")
	for _, c := range cases {
		for _, v := range []string{model.Pre, model.Post} {
			b.WriteString(model.Run(c, v).Row() + "\n")
		}
	}
	if err := os.WriteFile(filepath.Join(args[2], "cases.tsv"), []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(args[2], "sweep.csv"), []byte(model.SweepCSV()), 0o644)
}
