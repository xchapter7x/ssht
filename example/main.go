package main

import (
	"sync"

	"github.com/xchapter7x/ssht"
)

func main() {
	var wg sync.WaitGroup
	wg.Add(1)
	ssht.StartSSHServer(ssht.SSHTestServerConfig{
		AllowPasswordAuthN: false,
		Username:           "joe",
		Password:           "user",
		AllowKeyAuthN:      true,
	})
	wg.Wait()
}
