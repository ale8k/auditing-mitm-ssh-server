package main

import (
	"fmt"

	gliderssh "github.com/gliderlabs/ssh"
)

func newSshSessionError(msg string, s gliderssh.Session, err error) *sshSessionError {
	return &sshSessionError{
		Message:       msg,
		SessionID:     s.Context().SessionID(),
		ClientVersion: s.Context().ClientVersion(),
		ServerVersion: s.Context().ServerVersion(),
		UnderlyingErr: err,
	}
}

type sshSessionError struct {
	Message       string
	SessionID     string
	ClientVersion string
	ServerVersion string
	UnderlyingErr error
}

func (m *sshSessionError) Error() string {
	sessionErrMsg := fmt.Sprintf(
		"ssh session error: session id: %s client version: %s server version: %s message %s",
		m.SessionID,
		m.ClientVersion,
		m.ServerVersion,
		m.Message,
	)
	return fmt.Errorf(sessionErrMsg+" underlying err: %w", m.UnderlyingErr).Error()
}
