//go:build windows

package main

import (
	"log"
	"syscall"
)

func requireRoot() {
	shell32 := syscall.NewLazyDLL("shell32.dll")
	proc := shell32.NewProc("IsUserAnAdmin")
	ret, _, _ := proc.Call()
	if ret == 0 {
		log.Fatal("must run as Administrator (Npcap requires elevated privileges)")
	}
}
