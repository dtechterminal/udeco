package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/deco"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	devs, err := deco.DiscoverDeco(ctx, "192.168.0.255", true)
	if err != nil {
		log.Fatalf("Discover: %v", err)
	}
	for _, d := range devs {
		b, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(b))
	}
}
