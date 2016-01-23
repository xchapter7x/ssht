package main

import (
	"sync"

	"github.com/xchapter7x/ssht"
)

func main() {
	var wg sync.WaitGroup
	wg.Add(1)
	ssh := &ssht.SSHTestServer{
		AllowPasswordAuthN: false,
		Username:           "joe",
		Password:           "user",
		AllowKeyAuthN:      true,
		FakeResponseBytes:  []byte(`this is a test`),
		SSHCommandMatch:    "ls -lha",
	}
	ssh.Start()
	wg.Wait()
	ssh.Close()
}
