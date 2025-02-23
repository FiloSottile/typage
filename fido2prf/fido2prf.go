package fido2prf

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/typage/fido2prf/internal/ctap2cbor"
	"github.com/keys-pub/go-libfido2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func NewCredential(rpID, pin string) (string, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return "", err
	}
	if len(locs) == 0 {
		return "", errors.New("no FIDO2 devices found")
	}
	if len(locs) != 1 {
		return "", errors.New("multiple FIDO2 devices found, please remove all but one")
	}
	device, err := libfido2.NewDevice(locs[0].Path)
	if err != nil {
		return "", err
	}
	a, err := device.MakeCredential(
		// The client data hash is not useful without attestation.
		bytes.Repeat([]byte{0}, 32),
		libfido2.RelyingParty{ID: rpID},
		libfido2.User{
			// These are not used for non-resident credentials,
			// but the Go wrapper requires them.
			ID:   []byte{0},
			Name: "age-encryption.org/fido2prf",
		},
		libfido2.ES256,
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:         libfido2.False,
			UV:         libfido2.True,
		})
	if err != nil {
		return "", err
	}
	var identity []byte
	identity = ctap2cbor.AppendUint(identity, 1)
	identity = ctap2cbor.AppendBytes(identity, a.CredentialID)
	identity = ctap2cbor.AppendString(identity, rpID)
	identity = ctap2cbor.AppendArray(identity, "usb")
	return plugin.EncodeIdentity("fido2prf", identity), nil
}

type Identity struct {
	credentialID []byte
	relyingParty string
	transports   []string

	getPIN func() (string, error)
}

const label = "age-encryption.org/fido2prf"

func (i *Identity) assert(nonce []byte) ([]byte, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, err
	}
	if len(locs) == 0 {
		return nil, errors.New("no FIDO2 devices found")
	}
	for _, loc := range locs {
		device, err := libfido2.NewDevice(loc.Path)
		if err != nil {
			return nil, err
		}

		// First probe to check if the credential ID matches the device,
		// before requiring user interaction.
		if _, err := device.Assertion(
			i.relyingParty,
			make([]byte, 32),
			[][]byte{i.credentialID},
			"",
			&libfido2.AssertionOpts{
				UP: libfido2.False,
			},
		); errors.Is(err, libfido2.ErrNoCredentials) {
			continue
		} else if err != nil {
			return nil, err
		}

		pin, err := i.getPIN()
		if err != nil {
			return nil, err
		}

		assertion, err := device.Assertion(
			i.relyingParty,
			make([]byte, 32),
			[][]byte{i.credentialID},
			pin,
			&libfido2.AssertionOpts{
				Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
				HMACSalt:   hmacSecretSalt(nonce),
				UV:         libfido2.True,
			},
		)
		if err != nil {
			return nil, err
		}

		if assertion.HMACSecret == nil {
			return nil, errors.New("FIDO2 device doesn't support HMACSecret extension")
		}
		return assertion.HMACSecret, nil
	}

	return nil, errors.New("identity doesn't match any FIDO2 device")
}

func hmacSecretSalt(nonce []byte) []byte {
	// The PRF inputs for age-encryption.org/fido2prf are
	//
	//   "age-encryption.org/fido2prf" || 0x01 || nonce
	//
	// and
	//
	//   "age-encryption.org/fido2prf" || 0x02 || nonce
	//
	// The WebAuthn PRF inputs are then hashed into FIDO2 hmac-secret salts.
	//
	//   SHA-256("WebAuthn PRF" || 0x00 || input)
	//
	h := sha256.New()
	h.Write([]byte("WebAuthn PRF"))
	h.Write([]byte{0})
	h.Write([]byte(label))
	h.Write([]byte{1})
	h.Write(nonce)
	salt := h.Sum(nil)
	h.Reset()
	h.Write([]byte("WebAuthn PRF"))
	h.Write([]byte{0})
	h.Write([]byte(label))
	h.Write([]byte{2})
	h.Write(nonce)
	return h.Sum(salt)
}

func (i *Identity) Unwrap(s []*age.Stanza) ([]byte, error) {
	for _, stanza := range s {
		if stanza.Type != label {
			continue
		}
		if len(stanza.Args) != 1 {
			return nil, errors.New("fido2prf: invalid stanza: expected 1 argument")
		}
		nonce, err := base64.RawStdEncoding.Strict().DecodeString(stanza.Args[0])
		if err != nil || len(nonce) != 16 {
			return nil, errors.New("fido2prf: invalid nonce")
		}
		secret, err := i.assert(nonce)
		if err != nil {
			return nil, err
		}
		key := hkdf.Extract(sha256.New, secret, []byte(label))
		fileKey, err := aeadDecrypt(key, 16, stanza.Body)
		if err != nil {
			continue
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

func (i *Identity) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	secret, err := i.assert(nonce)
	if err != nil {
		return nil, err
	}
	key := hkdf.Extract(sha256.New, secret, []byte(label))
	ciphertext, err := aeadEncrypt(key, fileKey)
	if err != nil {
		return nil, err
	}
	return []*age.Stanza{{
		Type: label,
		Args: []string{base64.RawStdEncoding.Strict().EncodeToString(nonce)},
		Body: ciphertext,
	}}, nil
}

func NewIdentity(s string, getPIN func() (string, error)) (*Identity, error) {
	name, data, err := plugin.ParseIdentity(s)
	if err != nil {
		return nil, err
	}
	if name != "fido2prf" {
		return nil, errors.New("not a fido2prf identity")
	}
	return NewIdentityFromData(data, getPIN)
}

func NewIdentityFromData(data []byte, getPIN func() (string, error)) (*Identity, error) {
	var version uint16
	i := &Identity{getPIN: getPIN}
	s := ctap2cbor.String(data)
	if !s.ReadUint(&version) || version != 1 {
		return nil, errors.New("unsupported fido2prf version")
	}
	if !s.ReadBytes(&i.credentialID) || !s.ReadString(&i.relyingParty) ||
		!s.ReadArray(&i.transports) || !s.Empty() {
		return nil, errors.New("malformed fido2prf identity")
	}
	return i, nil
}

func aeadDecrypt(key []byte, size int, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) != size+aead.Overhead() {
		return nil, errors.New("encrypted value has unexpected length")
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Open(nil, nonce, ciphertext, nil)
}

func aeadEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plaintext, nil), nil
}
