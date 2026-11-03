package edge

import (
	"encoding/binary"
	"errors"
)

// The messages of be.session.v1 (be-protocol proto/be/session/v1/session.proto), encoded and decoded by hand: the
// plugin runs in Traefik's Yaegi interpreter, which takes the standard library only (the protobuf and gRPC modules
// use unsafe). Only the fields this package uses; unknown fields are skipped, as protobuf requires.

type exchangeResponse struct {
	AccessToken    string
	ExpiresAtMs    int64
	Principal      string
	SessionUntilMs int64
}

type cursor struct {
	Impl  string
	Epoch string
	Seq   uint64
}

type endedResponse struct {
	SessionDigests []string
	Next           *cursor
	Reset          bool
}

// Wire types.
const (
	wireVarint = 0
	wireBytes  = 2
)

func appendTag(b []byte, field, wire int) []byte {
	return binary.AppendUvarint(b, uint64(field<<3|wire))
}

func appendString(b []byte, field int, s string) []byte {
	if s == "" {
		return b
	}
	b = appendTag(b, field, wireBytes)
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

func appendVarint(b []byte, field int, v uint64) []byte {
	if v == 0 {
		return b
	}
	b = appendTag(b, field, wireVarint)
	return binary.AppendUvarint(b, v)
}

func appendMessage(b []byte, field int, m []byte) []byte {
	b = appendTag(b, field, wireBytes)
	b = binary.AppendUvarint(b, uint64(len(m)))
	return append(b, m...)
}

// exchangeRequest: session_digest = 1, renew_idle = 2.
func encodeExchange(digest string, renew bool) []byte {
	b := appendString(nil, 1, digest)
	if renew {
		b = appendVarint(b, 2, 1)
	}
	return b
}

// endedRequest: after = 1 (Cursor: impl = 1, epoch = 2, seq = 3), limit = 2.
func encodeEnded(after *cursor, limit uint32) []byte {
	var b []byte
	if after != nil {
		var c []byte
		c = appendString(c, 1, after.Impl)
		c = appendString(c, 2, after.Epoch)
		c = appendVarint(c, 3, after.Seq)
		b = appendMessage(b, 1, c)
	}
	return appendVarint(b, 2, uint64(limit))
}

var errMalformed = errors.New("malformed protobuf")

// fields calls f for each field of a message: its number, wire type, the varint value or the bytes.
func fields(b []byte, f func(field, wire int, v uint64, data []byte) error) error {
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return errMalformed
		}
		b = b[n:]
		field, wire := int(tag>>3), int(tag&7)
		switch wire {
		case wireVarint:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return errMalformed
			}
			b = b[n:]
			if err := f(field, wire, v, nil); err != nil {
				return err
			}
		case wireBytes:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return errMalformed
			}
			data := b[n : n+int(l)]
			b = b[n+int(l):]
			if err := f(field, wire, 0, data); err != nil {
				return err
			}
		case 1: // 64-bit
			if len(b) < 8 {
				return errMalformed
			}
			b = b[8:]
		case 5: // 32-bit
			if len(b) < 4 {
				return errMalformed
			}
			b = b[4:]
		default:
			return errMalformed
		}
	}
	return nil
}

func decodeExchange(b []byte) (exchangeResponse, error) {
	var r exchangeResponse
	err := fields(b, func(field, wire int, v uint64, data []byte) error {
		switch {
		case field == 1 && wire == wireBytes:
			r.AccessToken = string(data)
		case field == 2 && wire == wireVarint:
			r.ExpiresAtMs = int64(v)
		case field == 3 && wire == wireBytes:
			r.Principal = string(data)
		case field == 4 && wire == wireVarint:
			r.SessionUntilMs = int64(v)
		}
		return nil
	})
	return r, err
}

func decodeCursor(b []byte) (*cursor, error) {
	c := &cursor{}
	err := fields(b, func(field, wire int, v uint64, data []byte) error {
		switch {
		case field == 1 && wire == wireBytes:
			c.Impl = string(data)
		case field == 2 && wire == wireBytes:
			c.Epoch = string(data)
		case field == 3 && wire == wireVarint:
			c.Seq = v
		}
		return nil
	})
	return c, err
}

func decodeEnded(b []byte) (endedResponse, error) {
	var r endedResponse
	err := fields(b, func(field, wire int, v uint64, data []byte) error {
		switch {
		case field == 1 && wire == wireBytes:
			r.SessionDigests = append(r.SessionDigests, string(data))
		case field == 2 && wire == wireBytes:
			c, err := decodeCursor(data)
			if err != nil {
				return err
			}
			r.Next = c
		case field == 3 && wire == wireVarint:
			r.Reset = v != 0
		}
		return nil
	})
	return r, err
}
