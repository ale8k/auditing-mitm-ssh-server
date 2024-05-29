package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/moby/term"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	client := &NativeClient{
		Config:        ssh.ClientConfig{},
		ClientVersion: "super-special-jimm-ssh-client-thingy-ma-bob-1.0",
	}

	err := client.Shell()
	if err != nil && err.Error() != "exit status 255" {
		fmt.Println(err)
	}

}

// ExitError is a conveniance wrapper for (crypto/ssh).ExitError type.
type ExitError struct {
	Err      error
	ExitCode int
}

// Error implements error interface.
func (err *ExitError) Error() string {
	return err.Err.Error()
}

// Cause implements errors.Causer interface.
func (err *ExitError) Cause() error {
	return err.Err
}

func wrapError(err error) error {
	switch err := err.(type) {
	case *ssh.ExitError:
		e, s := &ExitError{Err: err, ExitCode: -1}, strings.TrimSpace(err.Error())
		// Best-effort attempt to parse exit code from os/exec error string,
		// like "Process exited with status 127".
		if i := strings.LastIndex(s, " "); i != -1 {
			if n, err := strconv.Atoi(s[i+1:]); err == nil {
				e.ExitCode = n
			}
		}
		return e
	default:
		return err
	}
}

// Client is a relic interface that both native and external client matched
type Client interface {
	// Output returns the output of the command run on the remote host.
	Output(command string) (string, error)

	// Shell requests a shell from the remote. If an arg is passed, it tries to
	// exec them on the server.
	Shell(args ...string) error

	// Start starts the specified command without waiting for it to finish. You
	// have to call the Wait function for that.
	//
	// The first two io.ReadCloser are the standard output and the standard
	// error of the executing command respectively. The returned error follows
	// the same logic as in the exec.Cmd.Start function.
	Start(command string) (io.ReadCloser, io.ReadCloser, error)

	// Wait waits for the command started by the Start function to exit. The
	// returned error follows the same logic as in the exec.Cmd.Wait function.
	Wait() error
}

// NativeClient is the structure for native client use
type NativeClient struct {
	Config        ssh.ClientConfig // Config defines the golang ssh client config
	ClientVersion string           // ClientVersion is the version string to send to the server when identifying
	openSession   *ssh.Session
}

// Auth contains auth info
type Auth struct {
	Passwords []string // Passwords is a slice of passwords to submit to the server
	Keys      []string // Keys is a slice of filenames of keys to try
	RawKeys   [][]byte // RawKeys is a slice of private keys to try
}

// Config is used to create new client.
type Config struct {
	User    string        // username to connect as, required
	Version string        // ssh client version, "SSH-2.0-Go" by default
	Timeout time.Duration // connect timeout, 30s by default
}

func (cfg *Config) version() string {
	if cfg.Version != "" {
		return cfg.Version
	}
	return "SSH-2.0-Go"
}

func (cfg *Config) timeout() time.Duration {
	if cfg.Timeout != 0 {
		return cfg.Timeout
	}
	return 30 * time.Second
}

func (cfg *Config) hostKey() ssh.HostKeyCallback {
	return ssh.InsecureIgnoreHostKey()
}

func (client *NativeClient) dialSuccess() bool {
	// if _, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", client.Hostname, client.Port), &client.Config); err != nil {
	// 	log.Debugf("Error dialing TCP: %s", err)
	// 	return false
	// }

	// TODO he just dials? why?
	return true
}

func (client *NativeClient) superSpecialJimmDial() (*ssh.Client, error) {
	// Connect to the proxy server
	conn, err := net.Dial("tcp", "localhost:17070")
	if err != nil {
		fmt.Println("Failed to connect to proxy:", err)
		return nil, nil
	}

	// Send the CONNECT request
	connectReq := fmt.Sprintf("CONNECT localhost:17070/ssh HTTP/1.1\r\nHost: localhost:17070\r\n\r\n")
	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		fmt.Println("Failed to send CONNECT request:", err)
		return nil, nil
	}

	// Read the response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Failed to read CONNECT response:", err)
		return nil, nil
	}
	response := string(buf[:n])
	fmt.Println("CONNECT response:", response)

	// Setup ssh client
	sshConfig := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Establish the SSH connection
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, "", sshConfig)
	if err != nil {
		fmt.Println("Failed to establish SSH connection:", err)
		return nil, nil
	}

	sshClient := ssh.NewClient(clientConn, chans, reqs)
	return sshClient, nil
}

func (client *NativeClient) session(command string) (*ssh.Session, error) {
	conn, err := client.superSpecialJimmDial()
	if err != nil {
		return nil, fmt.Errorf("Mysterious error dialing TCP for SSH (we already succeeded at least once) : %s", err)
	}

	return conn.NewSession()
}

// Output returns the output of the command run on the remote host.
func (client *NativeClient) Output(command string) (string, error) {
	session, err := client.session(command)
	if err != nil {
		return "", err
	}

	output, err := session.CombinedOutput(command)
	defer session.Close()

	return string(bytes.TrimSpace(output)), wrapError(err)
}

// Output returns the output of the command run on the remote host as well as a pty.
func (client *NativeClient) OutputWithPty(command string) (string, error) {
	session, err := client.session(command)
	if err != nil {
		return "", nil
	}

	fd := int(os.Stdin.Fd())

	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		return "", err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	// request tty -- fixes error with hosts that use
	// "Defaults requiretty" in /etc/sudoers - I'm looking at you RedHat
	if err := session.RequestPty("xterm", termHeight, termWidth, modes); err != nil {
		return "", err
	}

	output, err := session.CombinedOutput(command)
	defer session.Close()

	return string(bytes.TrimSpace(output)), wrapError(err)
}

// Start starts the specified command without waiting for it to finish. You
// have to call the Wait function for that.
func (client *NativeClient) Start(command string) (io.ReadCloser, io.ReadCloser, error) {
	session, err := client.session(command)
	if err != nil {
		return nil, nil, err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := session.Start(command); err != nil {
		return nil, nil, err
	}

	client.openSession = session
	return ioutil.NopCloser(stdout), ioutil.NopCloser(stderr), nil
}

// Wait waits for the command started by the Start function to exit. The
// returned error follows the same logic as in the exec.Cmd.Wait function.
func (client *NativeClient) Wait() error {
	err := client.openSession.Wait()
	_ = client.openSession.Close()
	client.openSession = nil
	return err
}

// Shell requests a shell from the remote. If an arg is passed, it tries to
// exec them on the server.
func (client *NativeClient) Shell(args ...string) error {
	var (
		termWidth, termHeight = 80, 24
	)
	conn, err := client.superSpecialJimmDial()
	if err != nil {
		return err
	}

	session, err := conn.NewSession()
	if err != nil {
		return err
	}

	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	modes := ssh.TerminalModes{
		ssh.ECHO: 1,
	}

	fd := os.Stdin.Fd()

	if term.IsTerminal(fd) {
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}

		defer term.RestoreTerminal(fd, oldState)

		winsize, err := term.GetWinsize(fd)
		if err == nil {
			termWidth = int(winsize.Width)
			termHeight = int(winsize.Height)
		}
	}

	if err := session.RequestPty("xterm", termHeight, termWidth, modes); err != nil {
		return err
	}

	if len(args) == 0 {
		if err := session.Shell(); err != nil {
			return err
		}

		// monitor for sigwinch
		go monWinCh(session, os.Stdout.Fd())

		session.Wait()
	} else {
		session.Run(strings.Join(args, " "))
	}

	return nil
}

// termSize gets the current window size and returns it in a window-change friendly
// format.
func termSize(fd uintptr) []byte {
	size := make([]byte, 16)

	winsize, err := term.GetWinsize(fd)
	if err != nil {
		binary.BigEndian.PutUint32(size, uint32(80))
		binary.BigEndian.PutUint32(size[4:], uint32(24))
		return size
	}

	binary.BigEndian.PutUint32(size, uint32(winsize.Width))
	binary.BigEndian.PutUint32(size[4:], uint32(winsize.Height))

	return size
}

// monWinCh watches for the system to signal a window resize and requests
// a window-change from the server.
func monWinCh(session *ssh.Session, fd uintptr) {
	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGWINCH)
	defer signal.Stop(sigs)

	// resize the tty if any signals received
	for range sigs {
		session.SendRequest("window-change", false, termSize(fd))
	}
}
