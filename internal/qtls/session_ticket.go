package qtls

import "bytes"

const extraPrefix = "quic-go1"

func AddSessionStateExtraPrefix(b []byte) []byte {
	return append([]byte(extraPrefix), b...)
}

func FindSessionStateExtraData(extras [][]byte) []byte {
	prefix := []byte(extraPrefix)
	for _, extra := range extras {
		if len(extra) < len(prefix) || !bytes.Equal(prefix, extra[:len(prefix)]) {
			continue
		}
		return extra[len(prefix):]
	}
	return nil
}
