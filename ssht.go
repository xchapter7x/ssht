package ssht

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kr/pty"

	"github.com/xchapter7x/lo"
	"golang.org/x/crypto/ssh"
)

type SSHTestServer struct {
	Port               int
	Host               string
	AllowKeyAuthN      bool
	PrivateKey         string
	PublicKey          string
	AllowPasswordAuthN bool
	Username           string
	Password           string
	FakeResponseBytes  []byte
	SSHCommandMatch    string
	Connected          bool
	listener           net.Listener
}

func (serverConfig *SSHTestServer) Close() error {
	serverConfig.Connected = false
	return serverConfig.listener.Close()
}

func (serverConfig *SSHTestServer) Start() (err error) {

	if serverConfig.Port == 0 {
		rand.Seed(time.Now().UTC().UnixNano())
		serverConfig.Port = rand.Intn(9999-1000) + 1000
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
		lo.G.Panic("Failed to parse private key")
	}
	config.AddHostKey(private)
	serverConfig.listener, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", serverConfig.Port))

	if err != nil {
		lo.G.Panic("Failed to listen on %d (%s)", serverConfig.Port, err)
	}
	lo.G.Info("Listening on %d...", serverConfig.Port)
	serverConfig.Connected = true

	go func() {
		for {
			tcpConn, err := serverConfig.listener.Accept()

			if err != nil {
				lo.G.Info("Failed to accept incoming connection (%s)", err)
				serverConfig.Connected = false
				break
			}
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)

			if err != nil {
				lo.G.Info("Failed to handshake (%s)", err)
				serverConfig.Connected = false
				break
			}
			lo.G.Info("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
			go ssh.DiscardRequests(reqs)
			go handleChannels(chans, serverConfig)
		}
	}()
	return
}

func handleChannels(chans <-chan ssh.NewChannel, config *SSHTestServer) {
	for newChannel := range chans {
		go handleChannel(newChannel, config)
	}
}

func handleChannel(newChannel ssh.NewChannel, config *SSHTestServer) {
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}
	connection, requests, err := newChannel.Accept()

	if err != nil {
		lo.G.Info("Could not accept channel (%s)", err)
		return
	}
	bash := exec.Command("bash")

	close := func() {
		connection.Close()
		_, err := bash.Process.Wait()

		if err != nil {
			lo.G.Info("Failed to exit bash (%s)", err)
		}
		lo.G.Info("Session closed")
	}
	lo.G.Info("Creating pty...")
	bashf, err := pty.Start(bash)

	if err != nil {
		lo.G.Info("Could not start pty (%s)", err)
		close()
		return
	}

	var once sync.Once
	var cmdBuffer = bytes.NewBufferString("")
	multiBashf := io.MultiWriter(cmdBuffer, bashf)

	go func() {
		io.Copy(multiBashf, connection)
		lo.G.Debug("done reading executor")
		once.Do(close)
	}()

	go func() {
		for {
			if strings.Contains(cmdBuffer.String(), config.SSHCommandMatch) {
				io.Copy(connection, bytes.NewBuffer(config.FakeResponseBytes))
				cmdBuffer.Reset()
			}
		}
	}()

	go func() {
		io.Copy(cmdBuffer, bashf)
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
