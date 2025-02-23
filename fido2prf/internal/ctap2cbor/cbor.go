// Package ctap2cbor implements a tiny subset of CTAP2's subset of CBOR,
// in order to encode and decode WebAuthn identities.
//
// Only major types 0 (unsigned integer), 2 (byte strings), 3 (text strings),
// and 4 (arrays, only containing text strings) are supported. Arguments are
// limited to 16-bit values.
//
// See https://www.imperialviolet.org/tourofwebauthn/tourofwebauthn.html#cbor.
package ctap2cbor

import "encoding/binary"

func appendTypeAndArgument(buf []byte, major uint8, arg uint16) []byte {
	if arg <= 23 {
		return append(buf, (major<<5)|uint8(arg))
	}
	if arg <= 0xff {
		return append(buf, (major<<5)|24, uint8(arg))
	}
	return append(buf, (major<<5)|25, uint8(arg>>8), uint8(arg))
}

func AppendUint(buf []byte, arg uint16) []byte {
	return appendTypeAndArgument(buf, 0, arg)
}

func AppendBytes(buf []byte, arg []byte) []byte {
	if len(arg) > 0xffff {
		panic("ctap2cbor: byte string too long")
	}
	buf = appendTypeAndArgument(buf, 2, uint16(len(arg)))
	return append(buf, arg...)
}

func AppendString(buf []byte, arg string) []byte {
	if len(arg) > 0xffff {
		panic("ctap2cbor: string too long")
	}
	buf = appendTypeAndArgument(buf, 3, uint16(len(arg)))
	return append(buf, arg...)
}

func AppendArray(buf []byte, arg ...string) []byte {
	if len(arg) > 0xffff {
		panic("ctap2cbor: array too long")
	}
	buf = appendTypeAndArgument(buf, 4, uint16(len(arg)))
	for _, s := range arg {
		buf = AppendString(buf, s)
	}
	return buf
}

type String []byte

func (s String) Empty() bool {
	return len(s) == 0
}

func (s *String) readTypeAndArgument() (major uint8, arg uint16, ok bool) {
	if len(*s) < 1 {
		return
	}
	major = (*s)[0] >> 5
	minor := (*s)[0] & 0x1f
	switch {
	case minor <= 23:
		arg = uint16(minor)
		*s = (*s)[1:]
	case minor == 24:
		if len(*s) < 2 {
			return
		}
		arg = uint16((*s)[1])
		*s = (*s)[2:]
	case minor == 25:
		if len(*s) < 3 {
			return
		}
		arg = binary.BigEndian.Uint16((*s)[1:])
		*s = (*s)[3:]
	default:
		return
	}
	ok = true
	return
}

func (s *String) ReadUint(out *uint16) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok || major != 0 {
		return false
	}
	*out = arg
	return true
}

func (s *String) ReadBytes(out *[]byte) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok || major != 2 {
		return false
	}
	if len(*s) < int(arg) {
		return false
	}
	*out = (*s)[:arg]
	*s = (*s)[arg:]
	return true
}

func (s *String) ReadString(out *string) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok || major != 3 {
		return false
	}
	if len(*s) < int(arg) {
		return false
	}
	*out = string((*s)[:arg])
	*s = (*s)[arg:]
	return true
}

func (s *String) ReadArray(out *[]string) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok || major != 4 {
		return false
	}
	for i := range arg {
		*out = append(*out, "")
		if !s.ReadString(&(*out)[i]) {
			return false
		}
	}
	return true
}
