package main

import (
	"fmt"
	"log"
	"os"

	"github.com/juju/zaputil/zapctx"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.EncodeTime = nil
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(config),
		zapcore.AddSync(os.Stdout),
		zapctx.LogLevel,
	)
	zapctx.Default = zap.New(core)
	zapctx.LogLevel.SetLevel(zapcore.DebugLevel)

	auditLogger := NewSSHAuditLogger()
	mitmServer := NewMITMAuditingSSHServer(auditLogger)

	fmt.Println("starting ssh server on port 2222...")
	log.Fatal(mitmServer.Start())
}

// func sftpHandler(s gliderssh.Session) {
// 	debugStream := io.Discard
// 	serverOptions := []sftp.ServerOption{
// 		sftp.WithDebug(debugStream),
// 	}
// 	server, err := sftp.NewServer(
// 		s,
// 		serverOptions...,
// 	)
// 	if err != nil {
// 		log.Printf("sftp server init error: %s\n", err)
// 		return
// 	}
// 	if err := server.Serve(); err == io.EOF {
// 		server.Close()
// 		fmt.Println("sftp client exited session.")
// 	} else if err != nil {
// 		fmt.Println("sftp server completed with error:", err)
// 	}
// }
