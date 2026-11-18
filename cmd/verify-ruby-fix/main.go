// verify-ruby-fix: reads the two customer YAML files, prints FV/AV entries
// produced by the fixed parseRubyVersion, and writes a minimal apps.tb.
// Usage: go run ./cmd/verify-ruby-fix <yaml1> [yaml2 ...]
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/vul-dbgen/updater/fetchers/apps"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: verify-ruby-fix <path/to/CVE.yml> ...")
		os.Exit(1)
	}

	out, err := os.Create("apps.tb")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create apps.tb:", err)
		os.Exit(1)
	}
	defer out.Close()

	enc := json.NewEncoder(out)

	for _, path := range os.Args[1:] {
		mv := apps.RubyYmlToModule(path)
		if mv == nil {
			fmt.Fprintf(os.Stderr, "SKIP %s (nil)\n", path)
			continue
		}
		fmt.Printf("=== %s  (%s) ===\n", mv.VulName, mv.ModuleName)
		fmt.Printf("  FV: %+v\n", mv.FixedVer)
		fmt.Printf("  AV: %+v\n\n", mv.AffectedVer)
		if err := enc.Encode(mv); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
		}
	}
	fmt.Println("wrote apps.tb")
}
