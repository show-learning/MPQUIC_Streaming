package main

import (
	"context"
	"log"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/testdata"
)

const alpn = "benchmark"

func main() {
	tlsConf := testdata.GetTLSConfig()
	tlsConf.NextProtos = []string{alpn}
	ln, err := quic.ListenAddr("localhost:1234", tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}
	for {
		sess, err := ln.Accept(context.Background())
		if err != nil {
			break
		}
		go handleConn(sess)
	}
}

func handleConn(sess quic.Session) {
	str, err := sess.OpenUniStream()
	if err != nil {
		log.Fatal(err)
	}
	data := make([]byte, 1<<20)
	for {
		if _, err := str.Write(data); err != nil {
			return
		}
	}
}
