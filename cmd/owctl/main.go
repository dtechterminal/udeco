// SPDX-License-Identifier: GPL-2.0-or-later

// owctl runs one AP-side action over SSH, for testing without the controller:
//
//	owctl bans | kick <mac> | ban <mac>... | unblock <mac>... | beep | led on|off|locate
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/antoniocosta/unifi-openwrt/internal/openwrt"
)

func main() {
	target := openwrt.TargetFlags(flag.CommandLine)
	flag.Parse()
	a := flag.Args()
	if len(a) == 0 {
		log.Fatal("usage: owctl bans | kick <mac> | ban <mac>... | unblock <mac>... | beep | led on|off|locate")
	}
	cl := openwrt.NewClient(*target)
	defer cl.Close()
	var err error
	switch {
	case a[0] == "bans":
		var out string
		out, err = cl.Bans()
		fmt.Print(out)
	case a[0] == "kick" && len(a) == 2:
		err = cl.Kick(a[1])
	case a[0] == "ban" && len(a) >= 2:
		err = cl.EnforceBlocked(a[1:])
	case a[0] == "unblock" && len(a) >= 2:
		err = cl.Unblock(a[1:])
	case a[0] == "beep":
		var ok bool
		ok, err = cl.Beep()
		fmt.Println("beeped:", ok)
	case a[0] == "led" && len(a) == 2:
		err = cl.SetLED(a[1])
	default:
		log.Fatal("bad arguments")
	}
	if err != nil {
		log.Fatal(err)
	}
}
