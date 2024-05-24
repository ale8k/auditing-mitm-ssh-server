package main

import (
	"context"
	"io"
	"strings"

	gliderssh "github.com/gliderlabs/ssh"
	"github.com/juju/zaputil/zapctx"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// SSHAuditLogger is a service capable of implementing the "ReceiveInput" method.
// For input audit logging purposes within a MITM SSH server.
type SSHAuditLogger interface {
	// ReceiveInput takes an inputChan, which sends input as it comes directly
	// from the client connected to the MITM server. It is called ONCE per SSH session
	// and additionally returns the Client's SSH session details.
	//
	// An example receive input may look like:
	// func (l *sshAuditLogger) ReceiveInput(inputChan <-chan []byte, sess SessionDetails) {
	// 	inputBuffer := &bytes.Buffer{}
	// 	for input := range inputChan {
	// 		inputBuffer.Write(input)
	// 		// Check for a command sent
	// 		if bytes.ContainsRune(input, '\r') {
	// 			io.Discard.Write(inputBuffer.Bytes())
	// 			inputBuffer.Reset()
	// 		}
	// 	}
	// }
	ReceivePTYInput(inputChan <-chan []byte, sess SessionDetails)

	// ReceiveCommandInput sends a session details as is, and the command used can be extracted
	// from the "ShellCommand" field.
	ReceiveCommandInput(sess SessionDetails)
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

func (m *MITMAuditingSSHServer) createSessionDetails(s gliderssh.Session) SessionDetails {
	return SessionDetails{
		ShellCommand:  s.Command(),
		Environ:       s.Environ(),
		ClientAddr:    s.RemoteAddr().String(),
		ClientVersion: s.Context().ClientVersion(),
		User:          s.User(),
		SessionID:     s.Context().SessionID(),
	}
}

// forward takes a stdinPipe from the target SSH server and does two things:
//
// 1. Forwards the MITM's client's input into the target session.
// 2. Forwards the MITM's client's input into the provided input channel for auditing and interception purposes.
func (m *MITMAuditingSSHServer) forward(ctx context.Context, stdinPipe io.WriteCloser, sess gliderssh.Session, inputChan chan<- []byte) {
	buf := make([]byte, 10)

	for {
		n, err := sess.Read(buf)
		if err != nil {
			zapctx.Error(ctx, "error reading from mitm session", zap.Error(err))
			return
		}
		if n > 0 {
			input := buf[:n]
			inputChan <- input

			if _, err := stdinPipe.Write([]byte(input)); err != nil {
				zapctx.Error(ctx, "error writing stdin pipe", zap.Error(err))
				return
			}
		}

	}
}

func (m *MITMAuditingSSHServer) setHandler() {
	m.server.Handle(func(s gliderssh.Session) {
		ctx := s.Context()

		var ptyReq gliderssh.Pty
		var ptyWindowChangeCh <-chan gliderssh.Window
		var isPty bool
		if len(s.Command()) == 0 {
			ptyReq, ptyWindowChangeCh, isPty = s.Pty()
		}

		// TODO: how do we know which machine to forward to?
		// One idea is take the ssh argument:
		// ssh user@mitm-server.com -p 2222 my-place-i-wanna-ssh-to
		// Do some auth checks
		// And if any commands are after the first shell arg, perform an exec
		// otherwise PTY?
		//
		// TODO(ale8k): No matter which route, make this pluggable into the MITM server
		targetConn, err := getTargetConnection()
		if err != nil {
			zapctx.Error(
				ctx,
				"get target connection and settings failed",
				zap.Error(err),
			)
			return
		}
		defer targetConn.Close()

		targetSession, err := targetConn.NewSession()
		if err != nil {
			zapctx.Error(
				ctx,
				"failed to create target session",
				zap.Error(err),
			)
			return
		}
		defer targetSession.Close()

		if isPty {
			modes := ssh.TerminalModes{
				ssh.ECHO:          1,     // disable echoing
				ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
				ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
			}
			if err := targetSession.RequestPty(ptyReq.Term, ptyReq.Window.Height, ptyReq.Window.Width, modes); err != nil {
				zapctx.Error(
					ctx,
					"target session request pty failed",
					zap.Error(err),
				)
				return
			}

			zapctx.Debug(ctx, "piping")
			zapctx.Debug(ctx, "starting stdin pipe...")
			stdinPipe, err := targetSession.StdinPipe()
			if err != nil {
				zapctx.Error(
					ctx,
					"failed to get target session stdin pipe",
					zap.Error(err),
				)
				return
			}
			inputChan := make(chan []byte)

			zapctx.Debug(ctx, "starting input forwarding...")
			go m.forward(ctx, stdinPipe, s, inputChan)

			// Audit Logger interception.
			go m.auditLogger.ReceivePTYInput(inputChan, m.createSessionDetails(s))

			targetSession.Stdout = s
			targetSession.Stderr = s.Stderr()

			zapctx.Debug(ctx, "getting login shell...")
			if err := targetSession.Shell(); err != nil {
				zapctx.Error(
					ctx,
					"failed to start login shell",
					zap.Error(err),
				)
				return
			}

			go m.handleSSHTargetWindowChanges(
				ptyWindowChangeCh,
				targetSession,
			)

			zapctx.Debug(ctx, "waiting for remote session to exit")
			if err := targetSession.Wait(); err != nil {
				zapctx.Error(
					ctx,
					"remote session exit failed",
					zap.Error(err),
				)
				return
			}
			zapctx.Debug(ctx, "remote session exited")
		} else {
			command := s.Command()
			m.auditLogger.ReceiveCommandInput(m.createSessionDetails(s))
			zapctx.Debug(ctx, "executing command on target SSH server", zap.Any("command", command))
			out, err := targetSession.CombinedOutput(strings.Join(command, " "))
			if err != nil {
				zapctx.Error(
					ctx,
					"failed to execute command",
					zap.Error(err),
				)
				return
			}
			io.WriteString(s, string(out))
		}
	})
}
