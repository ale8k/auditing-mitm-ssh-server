package main

import (
	"fmt"
	"io"
	"strings"

	gliderssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

// SSHAuditLogger is a service capable of implementing the "ReceiveInput" method.
// For input audit logging purposes within a MITM SSH server.
type SSHAuditLogger interface {
	// ReceiveInput takes an inputChan, which sends input as it comes directly
	// from the client connected to the MITM server. It is called ONCE per SSH session
	// and additionally returns the Client's SSH session details.
	ReceiveInput(inputChan <-chan []byte, sess SessionDetails)
}

// SessionDetails contains the client's details for this SSH session.
type SessionDetails struct {
	// Command returns a shell parsed slice of arguments that were provided by the user.
	// Shell parsing splits the command string according to POSIX shell rules,
	// which considers quoting not just whitespace.
	ShellCommand []string

	// Environ returns a copy of strings representing the environment set by the user
	// for this session, in the form "key=value".
	Environ []string

	// ClientAddr is the remote client address.
	ClientAddr string

	// ClientVersion is the client's SSH client version.
	ClientVersion string

	// User is the user the client is connecting as.
	User string

	// SessionID is a hash identifier for the session.
	SessionID string
}

// NewMITMAuditingSSHServer returns a new MITMAuditingSSHServer, it takes
// an SSHAuditLogger to allow logging of user's input from the client side.
func NewMITMAuditingSSHServer(l SSHAuditLogger) *MITMAuditingSSHServer {
	mitm := &MITMAuditingSSHServer{
		server: &gliderssh.Server{
			Addr: ":2222",
			// SubsystemHandlers: map[string]gliderssh.SubsystemHandler{
			// 	"sftp": sftpHandler,
			// 	"scp":  sftpHandler,
			// },
		},
		auditLogger: l,
	}
	mitm.setHandler()
	return mitm
}

// MITMAuditingSSHServer is a man-in-the-middle SSH server capable of
// auditing users input.
type MITMAuditingSSHServer struct {
	server      *gliderssh.Server
	auditLogger SSHAuditLogger
}

// Start starts the SSH server.
func (m *MITMAuditingSSHServer) Start() error {
	return m.server.ListenAndServe()
}

// handleSSHTargetWindowChanges takes the internal SSH servers channel of window changes
// and updates the target sessions window.
//
// This is expected to be run in a separate routine!
func (m *MITMAuditingSSHServer) handleSSHTargetWindowChanges(
	ptyWindowChangeCh <-chan gliderssh.Window,
	targetSession *ssh.Session,
) {
	for change := range ptyWindowChangeCh {
		targetSession.WindowChange(change.Height, change.Width)
	}
}

// forward takes a stdinPipe from the target SSH server and does two things:
//
// 1. Forwards the MITM's client's input into the target session.
// 2. Forwards the MITM's client's input into the provided input channel for auditing and interception purposes.
func (m *MITMAuditingSSHServer) forward(stdinPipe io.WriteCloser, sess gliderssh.Session, inputChan chan<- []byte) {
	buf := make([]byte, 10)

	for {
		n, err := sess.Read(buf)
		if err != nil {
			// HANDLE BREAKS, DON'T DO THIS
			fmt.Println("Closing glider connection")
			fmt.Println(fmt.Errorf("failed to read: %w", err))
			sess.Close()
			return
		}
		if n > 0 {
			input := buf[:n]
			inputChan <- input

			if _, err := stdinPipe.Write([]byte(input)); err != nil {
				fmt.Println("Closing glider connection")
				fmt.Println(fmt.Errorf("input write error occured: %w", err))
				fmt.Println(sess.Close())
				return
			}
		}

	}
}

func (m *MITMAuditingSSHServer) setHandler() {
	m.server.Handle(func(s gliderssh.Session) {
		// TODO: how do we know which machine to forward to?
		targetConn, err := getTargetConnection()
		if err != nil {
			fmt.Println(newSshSessionError("get target connection and settings failed", s, err))
			return
		}
		defer targetConn.Close()

		targetSession, err := targetConn.NewSession()
		if err != nil {
			fmt.Println(newSshSessionError("failed to create target session", s, err))
			return
		}
		defer targetSession.Close()

		var ptyReq gliderssh.Pty
		var ptyWindowChangeCh <-chan gliderssh.Window
		var isPty bool
		if len(s.Command()) == 0 {
			ptyReq, ptyWindowChangeCh, isPty = s.Pty()
		}

		if isPty {
			modes := ssh.TerminalModes{
				ssh.ECHO:          1,     // disable echoing
				ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
				ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
			}
			if err := targetSession.RequestPty(ptyReq.Term, ptyReq.Window.Height, ptyReq.Window.Width, modes); err != nil {
				fmt.Println(newSshSessionError("target session request pty failed", s, err))
				return
			}

			fmt.Println("Debug: Piping")

			fmt.Println("Debug: Stdin Pipe")
			stdinPipe, err := targetSession.StdinPipe()
			if err != nil {
				fmt.Println(newSshSessionError("failed to get target session stdin pipe", s, err))
				return
			}
			inputChan := make(chan []byte)
			go m.forward(stdinPipe, s, inputChan)

			// Audit Logger interception.
			go m.auditLogger.ReceiveInput(inputChan, SessionDetails{
				ShellCommand:  s.Command(),
				Environ:       s.Environ(),
				ClientAddr:    s.RemoteAddr().String(),
				ClientVersion: s.Context().ClientVersion(),
				User:          s.User(),
				SessionID:     s.Context().SessionID(),
			})

			targetSession.Stdout = s
			targetSession.Stderr = s.Stderr()

			fmt.Println("Debug: Starting login shell")
			if err := targetSession.Shell(); err != nil {
				fmt.Println(newSshSessionError("failed to start login shell", s, err))
				return
			}

			go m.handleSSHTargetWindowChanges(
				ptyWindowChangeCh,
				targetSession,
			)

			fmt.Println("Debug: Waiting for remote session to exit")
			if err := targetSession.Wait(); err != nil {
				fmt.Println(newSshSessionError("remote session exit failed", s, err))
				return
			}
			fmt.Println("Debug: Remote session exited")
		} else {
			command := s.Command()
			fmt.Printf("Executing command on target SSH server: %s", command)
			out, err := targetSession.CombinedOutput(strings.Join(command, " "))
			if err != nil {
				fmt.Println(newSshSessionError("failed to execute command", s, err))
				return
			}
			io.WriteString(s, string(out))
		}
	})
}
