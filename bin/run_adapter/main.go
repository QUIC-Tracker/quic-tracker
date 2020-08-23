package main

import (
	"fmt"
	"github.com/tiferrei/quic-tracker/adapter"
)


func main() {
	adapter, err := adapter.NewAdapter("0.0.0.0:3333", "implementation:4433", "www.example.org")
	if err != nil {
		fmt.Printf("Failed to create Adapter: %v", err.Error())
		return
	}

	adapter.Run()
}
