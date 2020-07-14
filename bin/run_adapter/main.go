package main

import (
	"fmt"
	"github.com/tiferrei/quic-tracker/adapter"
)


func main() {
	adapter, err := adapter.NewAdapter("127.0.0.1:3333", "quic.tech:4433", "quic.tech")
	if err != nil {
		fmt.Printf("Failed to create Adapter: %v", err.Error())
		return
	}
	fmt.Println("Successfuly created new Adapter.")

	adapter.Run()
}
