package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh"
)

// /model/<uuid>/machine/<number>/lxd/<number>/lxd/<number>/ssh
// /model/<uuid>/application/<name>/unit/<number>/ssh?container=<container name>
func getTargetConnection() (*ssh.Client, error) {
	// Get IP
	cmd := exec.Command("sh", "-c", "multipass ls --format json | jq -r '.list[] | select(.name == \"test\") | .ipv4[0]'")

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error executing command:", err)
		return nil, err
	}

	ipv4 := strings.TrimSpace(string(output))
	fmt.Println("IPv4 address of instance 'test':", ipv4)

	targetHost := ipv4 + ":22"
	targetUser := "test"
	targetPrivateKeyBytes, err := os.ReadFile("./ssh/key")
	if err != nil {
		fmt.Println("cannot find key")
		os.Exit(1)
	}

	targetPrivateKey, err := ssh.ParsePrivateKey(targetPrivateKeyBytes)
	if err != nil {
		fmt.Println("failed to parse priv key")
		os.Exit(1)
	}

	// Connect to the target SSH server
	targetConfig := &ssh.ClientConfig{
		User: targetUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(targetPrivateKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	targetConn, err := ssh.Dial("tcp", targetHost, targetConfig)
	if err != nil {
		fmt.Printf("Failed to connect to target SSH server: %v", err)
		return nil, err
	}

	return targetConn, nil
}
