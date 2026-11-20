// SPDX-License-Identifier: GPL-2.0-or-later

// owprobe reads an OpenWrt AP once (read-only) and prints the UniFi fields
// the daemon would send. Client MACs are shortened in the output.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/openwrt"
)

func main() {
	target := openwrt.TargetFlags(flag.CommandLine)
	raw := flag.String("raw", "", "also save the raw collection output here (mode 600)")
	flag.Parse()
	cl := openwrt.NewClient(*target)
	defer cl.Close()
	s1, err := cl.Collect()
	if err != nil {
		log.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	s2, err := cl.Collect()
	if err != nil {
		log.Fatal(err)
	}
	if *raw != "" {
		out, _ := cl.Run(openwrt.CollectScript())
		os.WriteFile(*raw, out, 0o600)
	}
	fmt.Printf("model=%q host=%q release=%q mac=%s ip=%s/%s gw=%s uptime=%d radios=%d ports=%d\n",
		s2.Model, s2.Hostname, s2.Release, s2.MAC, s2.IP, s2.Netmask, s2.Gateway, s2.Uptime, len(s2.Radios), len(s2.Ports))
	b, _ := json.MarshalIndent(s2.Fields(s1, openwrt.CfgInfo{}, nil), "", "  ")
	fmt.Println(regexp.MustCompile(`"([0-9a-f]{2}):([0-9a-f]{2}):[0-9a-f:]{11}"`).ReplaceAllString(string(b), `"$1:$2:…"`))
}
