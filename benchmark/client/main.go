package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	_ "net/http/pprof"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
)

const alpn = "benchmark"

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6061", nil))
	}()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
	}
	sess, err := quic.DialAddr("localhost:1234", tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}
	str, err := sess.AcceptUniStream(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	b := make([]byte, 1<<10)
	var total uint64 // to be used as an atomic
	go func() {
		var lastTotal uint64
		lastTime := time.Now()
		for t := range time.NewTicker(time.Second).C {
			tot := atomic.LoadUint64(&total)
			log.Printf("Current bandwidth: %f MiB/s\n", float64(tot-lastTotal)/(1<<20*t.Sub(lastTime).Seconds()))
			lastTotal = tot
			lastTime = t
		}
	}()
	for {
		n, err := str.Read(b)
		if err != nil {
			log.Fatal(err)
		}
		atomic.AddUint64(&total, uint64(n))
	}
}
