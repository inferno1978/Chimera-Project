//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/daniellavrushin/b4/config"
)

func main() {
	cfg := config.NewSetConfig()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
		os.Exit(1)
	}

	dest := "http/ui/src/models/defaults.json"
	if len(os.Args) > 1 {
		dest = os.Args[1]
	}

	if err := os.WriteFile(dest, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("defaults.json written to %s\n", dest)
}
