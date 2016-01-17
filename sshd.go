package ssht

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"reflect"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

type SSHTestServerConfig struct {
	Port               int
	Host               string
	AllowKeyAuthN      bool
	PrivateKey         string
	PublicKey          string
	AllowPasswordAuthN bool
	Username           string
	Password           string
}

func StartSSHServer(serverConfig SSHTestServerConfig) net.Listener {

	if serverConfig.Port == 0 {
		rand.Seed(time.Now().UTC().UnixNano())
		serverConfig.Port = rand.Intn(9999)
	}
	config := &ssh.ServerConfig{}

	if serverConfig.AllowKeyAuthN {
		signer, _ := ssh.ParsePrivateKey([]byte(PrivateKey))
		config.AddHostKey(signer)
		config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (perm *ssh.Permissions, err error) {
			pubkey := signer.PublicKey()

			if !reflect.DeepEqual(pubkey.Marshal(), key.Marshal()) {
				err = errors.New("invalid key")
			}
			return
		}
	}

	if serverConfig.AllowPasswordAuthN {
		config.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in a production setting.
			if serverConfig.AllowPasswordAuthN == true && c.User() == serverConfig.Username && string(pass) == serverConfig.Password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		}
	}
	privateBytes := []byte(PrivateKey)
	private, err := ssh.ParsePrivateKey(privateBytes)

	if err != nil {
		log.Fatal("Failed to parse private key")
	}
	config.AddHostKey(private)
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", serverConfig.Port))

	if err != nil {
		log.Fatalf("Failed to listen on %d (%s)", serverConfig.Port, err)
	}
	log.Printf("Listening on %d...", serverConfig.Port)

	go func() {
		for {
			tcpConn, err := listener.Accept()

			if err != nil {
				log.Printf("Failed to accept incoming connection (%s)", err)
				continue
			}
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)

			if err != nil {
				log.Printf("Failed to handshake (%s)", err)
				continue
			}
			log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
			go ssh.DiscardRequests(reqs)
			go handleChannels(chans)
		}
	}()
	return listener
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}
	connection, requests, err := newChannel.Accept()

	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}
	bash := exec.Command("bash")

	close := func() {
		connection.Close()
		_, err := bash.Process.Wait()

		if err != nil {
			log.Printf("Failed to exit bash (%s)", err)
		}
		log.Printf("Session closed")
	}
	log.Print("Creating pty...")
	bashf, err := pty.Start(bash)

	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		close()
		return
	}

	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
	}()

	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

// =======================

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

// Borrowed from https://github.com/creack/termios/blob/master/win/win.go
