package main

import (
	"fmt"
	"github.com/tiferrei/quic-tracker/adapter"
)


func main() {
	adapter, err := adapter.NewAdapter("0.0.0.0:3333", "server:4433", "quic.tiferrei.com")
	if err != nil {
		fmt.Printf("Failed to create Adapter: %v", err.Error())
		return
	}

	adapter.Run()
}
