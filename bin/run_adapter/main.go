package main

import (
	"fmt"
	"github.com/tiferrei/quic-tracker/adapter"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)


func main() {
	adapterAddress := readEnvWithFallback("ADAPTER_ADDRESS", "0.0.0.0:3333")
	sulAddress := readEnvWithFallback("SUL_ADDRESS", "implementation:4433")
	sulName := readEnvWithFallback("SUL_NAME", "quic.tiferrei.com")
	http3 := readEnvWithFallback("HTTP3", "false")

	http3Bool, err := strconv.ParseBool(http3)
	if err != nil {
		fmt.Printf("Error: Invalid HTTP3 value, must be bool.")
		return
	}

	sulAdapter, err := adapter.NewAdapter(adapterAddress, sulAddress, sulName, http3Bool)
	if err != nil {
		fmt.Printf("Failed to create Adapter: %v", err.Error())
		return
	}

	SetupCloseHandler(sulAdapter)
	defer func() {
		sulAdapter.Stop()
	}()

	sulAdapter.Run()
}

func readEnvWithFallback(envName string, fallback string) string {
	value, exists := os.LookupEnv(envName)
	if !exists {
		value = fallback
	}
	return value
}

func SetupCloseHandler(adapter *adapter.Adapter) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		adapter.Stop()
		os.Exit(0)
	}()
}
