//go:build go1.22

package qtls

import (
	"crypto/tls"
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
)

type (
	QUICConn                 = tls.QUICConn
	QUICConfig               = tls.QUICConfig
	QUICEvent                = tls.QUICEvent
	QUICEventKind            = tls.QUICEventKind
	QUICEncryptionLevel      = tls.QUICEncryptionLevel
	QUICSessionTicketOptions = tls.QUICSessionTicketOptions
	AlertError               = tls.AlertError
)

const (
	QUICEncryptionLevelInitial     = tls.QUICEncryptionLevelInitial
	QUICEncryptionLevelEarly       = tls.QUICEncryptionLevelEarly
	QUICEncryptionLevelHandshake   = tls.QUICEncryptionLevelHandshake
	QUICEncryptionLevelApplication = tls.QUICEncryptionLevelApplication
)

const (
	QUICNoEvent                     = tls.QUICNoEvent
	QUICSetReadSecret               = tls.QUICSetReadSecret
	QUICSetWriteSecret              = tls.QUICSetWriteSecret
	QUICWriteData                   = tls.QUICWriteData
	QUICTransportParameters         = tls.QUICTransportParameters
	QUICTransportParametersRequired = tls.QUICTransportParametersRequired
	QUICRejectedEarlyData           = tls.QUICRejectedEarlyData
	QUICHandshakeDone               = tls.QUICHandshakeDone
	QUICResumeSession               = tls.QUICResumeSession
	QUICStoreSession                = tls.QUICStoreSession
)

func QUICServer(config *QUICConfig) *QUICConn { return tls.QUICServer(config) }
func QUICClient(config *QUICConfig) *QUICConn { return tls.QUICClient(config) }

func SetupConfigForServer(qconf *QUICConfig, _ bool, _ func() []byte, _ func([]byte, bool) bool) {
	conf := qconf.TLSConfig
	qconf.EnableStoreSessionEvent = true

	// Workaround for https://github.com/golang/go/issues/60506.
	// This initializes the session tickets _before_ cloning the config.
	_, _ = conf.DecryptTicket(nil, tls.ConnectionState{})

	conf = conf.Clone()
	conf.MinVersion = tls.VersionTLS13
	qconf.TLSConfig = conf
}

func SetupConfigForClient(qconf *QUICConfig, _ func() []byte, _ func([]byte) bool) {
	qconf.EnableStoreSessionEvent = true
}

func ToTLSEncryptionLevel(e protocol.EncryptionLevel) tls.QUICEncryptionLevel {
	switch e {
	case protocol.EncryptionInitial:
		return tls.QUICEncryptionLevelInitial
	case protocol.EncryptionHandshake:
		return tls.QUICEncryptionLevelHandshake
	case protocol.Encryption1RTT:
		return tls.QUICEncryptionLevelApplication
	case protocol.Encryption0RTT:
		return tls.QUICEncryptionLevelEarly
	default:
		panic(fmt.Sprintf("unexpected encryption level: %s", e))
	}
}

func FromTLSEncryptionLevel(e tls.QUICEncryptionLevel) protocol.EncryptionLevel {
	switch e {
	case tls.QUICEncryptionLevelInitial:
		return protocol.EncryptionInitial
	case tls.QUICEncryptionLevelHandshake:
		return protocol.EncryptionHandshake
	case tls.QUICEncryptionLevelApplication:
		return protocol.Encryption1RTT
	case tls.QUICEncryptionLevelEarly:
		return protocol.Encryption0RTT
	default:
		panic(fmt.Sprintf("unexpect encryption level: %s", e))
	}
}

func SendSessionTicket(c *QUICConn, allow0RTT bool, extra []byte) error {
	return c.SendSessionTicket(tls.QUICSessionTicketOptions{
		EarlyData: allow0RTT,
		Extra:     [][]byte{extra},
	})
}
