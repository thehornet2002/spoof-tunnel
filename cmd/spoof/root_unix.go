//go:build !windows

package main

import (
	"log"
	"os"
)

func requireRoot() {
	if os.Geteuid() != 0 {
		log.Fatal("must run as root (raw sockets require CAP_NET_RAW)")
	}
}
