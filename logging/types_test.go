package logging

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Types", func() {
	It("has a string representation for packet types", func() {
		Expect(PacketTypeInitial.String()).To(Equal("Initial"))
		Expect(PacketTypeHandshake.String()).To(Equal("Handshake"))
		Expect(PacketType1RTT.String()).To(Equal("1-RTT"))
		Expect(PacketType0RTT.String()).To(Equal("0-RTT"))
		Expect(PacketTypeRetry.String()).To(Equal("Retry"))
		Expect(PacketTypeVersionNegotiation.String()).To(Equal("Version Negotiation"))
		Expect(PacketTypeStatelessReset.String()).To(Equal("Stateless Reset"))
		Expect(PacketTypeNotDetermined.String()).To(Equal("not determined"))
		Expect(PacketType(42).String()).To(Equal("unknown packet type: 42"))
	})
})
