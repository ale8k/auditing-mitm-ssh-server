package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"
)

func NewSSHAuditLogger() *sshAuditLogger {
	return &sshAuditLogger{
		logs: make([]sshAuditLog, 0),
	}
}

type sshAuditLogger struct {

	// A slice of logs to be written upon session closure
	logs []sshAuditLog
}

type sshAuditLog struct {
	SessionId     string
	User          string
	ClientVersion string
	ClientsAddr   string
	RawCommand    []byte
	Command       string
	Timestamp     time.Time
}

func (l *sshAuditLogger) ReceiveInput(inputChan <-chan []byte, sess SessionDetails) {
	inputBuffer := &bytes.Buffer{}
	for input := range inputChan {
		inputBuffer.Write(input)

		if bytes.ContainsRune(input, '\r') {
			fmt.Println("Log being sent")
			l.sendLog(inputBuffer, sess)
		}
	}
}

func (l *sshAuditLogger) sendLog(inputBuffer *bytes.Buffer, sess SessionDetails) {
	rawCommand := inputBuffer.Bytes()
	runes := bytes.Runes(rawCommand)
	command := string(runes)

	log := sshAuditLog{
		SessionId:     sess.SessionID,
		User:          sess.User,
		ClientVersion: sess.ClientVersion,
		ClientsAddr:   sess.ClientAddr,
		RawCommand:    rawCommand,
		Command:       command,
		Timestamp:     time.Now(),
	}
	l.logs = append(l.logs, log)
	fmt.Println("Log created")
	loggylog, _ := json.MarshalIndent(log, "", " ")
	fmt.Println(string(loggylog))
	inputBuffer.Reset()
}

// A basic attempt to remove backspace, del, ctrl+backspace and ctrl+c from
// human readable outputs
func handleRemovals(bytes []byte) string {
	var result []rune
	for i := 0; i < len(bytes); {
		r, size := utf8.DecodeRune(bytes[i:])
		switch r {
		case '\b', 127: // Backspace or DEL
			if len(result) > 0 {
				result = result[:len(result)-1] // Remove the last rune
			}
		case 3: // Ctrl+C
			return ""
		case 23: // Ctrl+backspace
			// Find the index of the first previous whitespace character
			idx := len(result)
			for idx > 0 {
				r := result[idx-1]
				if unicode.IsSpace(r) {
					break
				}
				idx--
			}
			result = result[:idx] // Remove from cursor to previous whitespace
		default:
			result = append(result, r)
		}
		i += size
	}
	result = result[:len(result)-1] // Remove final \r (it'll always be there anyway as they're submitting a command)
	return string(result)
}
