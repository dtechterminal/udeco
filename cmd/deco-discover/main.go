package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dtechterminal/udeco/internal/deco"
)

func main() {
	ip := "192.168.0.241"
	if len(os.Args) > 1 {
		ip = os.Args[1]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	infos, err := deco.DiscoverDeco(ctx, ip, false)
	if err != nil {
		log.Fatalf("DiscoverDeco: %v", err)
	}
	for _, info := range infos {
		b, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(b))
		fmt.Printf("SSH port: %d\n", info.SSHPort())
	}
}
