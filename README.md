# Auditing MITM SSH Server with HTTP CONNECT SSH
This repository contains a packaged auditing capable SSH server.

See `mitm_server.go` for the packaged SSH server.

It is expected you bring your own `SSHAuditLogger` implementation for collection and persistence of the 
logs.

The receive logs from a PTY, it may look like:
```go
func (l *sshAuditLogger) ReceiveInput(inputChan <-chan []byte, sess SessionDetails) {
	inputBuffer := &bytes.Buffer{}

	for input := range inputChan {
		inputBuffer.Write(input)

		// Check for a command sent
		if bytes.ContainsRune(input, '\r') {
			io.Discard.Write(inputBuffer.Bytes())
			inputBuffer.Reset()
		}
	}
}
```

To receive logs from a single command, it may look like:
```go
func (l *sshAuditLogger) ReceiveCommandInput(sess SessionDetails) {
	b, _ := json.MarshalIndent(sess, "", " ")
	fmt.Println(string(b))
}
```

Steps to test this:
1. Launch mp vm via: `multipass launch --cloud-init cloud-init.yaml --name test`
2. Test ssh with your custom user via: `ssh -i ./ssh/key test@$(multipass ls --format json | jq -r '.list[] | select(.name == "test") | .ipv4[0]')`
3. Run a command: `go run ./cmd/client`