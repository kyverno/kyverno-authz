package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/kyverno/kyverno-authz/pkg/commands/root"
	"github.com/spf13/cobra/doc"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func main() {
	out := flag.String("out", "./docs/cli", "output directory or file")
	format := flag.String("format", "markdown", "markdown|man|rest")
	front := flag.Bool("frontmatter", false, "prepend simple YAML front matter to markdown")
	cmdPath := flag.String("command", "", "specific command path to generate docs for (e.g., 'serve envoy authz-server')")
	outputFile := flag.String("output-file", "", "output file name (only used with -command, overrides default naming)")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}

	rootCmd := root.Command()
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	rootCmd = rootCmd.Root()

	rootCmd.DisableAutoGenTag = true // stable, reproducible files (no timestamp footer)

	// If a specific command path is provided, find and use that command instead
	targetCmd := rootCmd
	if *cmdPath != "" {
		parts := strings.Fields(*cmdPath)
		for _, part := range parts {
			found := false
			for _, child := range targetCmd.Commands() {
				if child.Name() == part {
					targetCmd = child
					found = true
					break
				}
				// Check aliases
				for _, alias := range child.Aliases {
					if alias == part {
						targetCmd = child
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				log.Fatalf("command path '%s' not found: could not find '%s' under '%s'", *cmdPath, part, targetCmd.CommandPath())
			}
		}
	}

	switch *format {
	case "markdown":
		// If a specific command and output file are provided, generate to a single file
		if *cmdPath != "" && *outputFile != "" {
			outputPath := filepath.Join(*out, *outputFile)
			if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
				log.Fatal(err)
			}
			file, err := os.Create(outputPath)
			if err != nil {
				log.Fatal(err)
			}
			defer closeFile(file)

			if *front {
				base := filepath.Base(*outputFile)
				name := strings.TrimSuffix(base, filepath.Ext(base))
				title := cases.Title(language.Und, cases.NoLower).String(strings.ReplaceAll(name, "_", " "))
				frontmatter := fmt.Sprintf("---\ntitle: %q\nslug: %q\ndescription: \"CLI reference for %s\"\n---\n\n", title, name, title)
				if _, err := file.WriteString(frontmatter); err != nil {
					log.Fatal(err)
				}
			}
			if err := doc.GenMarkdown(targetCmd, file); err != nil {
				log.Fatal(err)
			}
		} else {
			// Generate tree of commands
			if *front {
				prep := func(filename string) string {
					base := filepath.Base(filename)
					name := strings.TrimSuffix(base, filepath.Ext(base))
					title := strings.ReplaceAll(name, "_", " ")
					return fmt.Sprintf("---\ntitle: %q\nslug: %q\ndescription: \"CLI reference for %s\"\n---\n\n", title, name, title)
				}
				link := func(name string) string { return strings.ToLower(name) }
				if err := doc.GenMarkdownTreeCustom(targetCmd, *out, prep, link); err != nil {
					log.Fatal(err)
				}
			} else {
				if err := doc.GenMarkdownTree(targetCmd, *out); err != nil {
					log.Fatal(err)
				}
			}
		}
	case "man":
		hdr := &doc.GenManHeader{Title: strings.ToUpper(targetCmd.Name()), Section: "1"}
		if err := doc.GenManTree(targetCmd, hdr, *out); err != nil {
			log.Fatal(err)
		}
	case "rest":
		if err := doc.GenReSTTree(targetCmd, *out); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown format: %s", *format)
	}
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		log.Fatal(err)
	}
}
