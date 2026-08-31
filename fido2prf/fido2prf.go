package fido2prf

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/typage/fido2prf/internal/ctap2cbor"
	"github.com/telesma-app/ctap/authenticator"
	directhid "github.com/telesma-app/ctap/backend/hid"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/webauthn"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func NewCredential(rpID, pin string) (string, error) {
	ctx := context.Background()
	var paths []string
	for info, err := range directhid.Devices(ctx) {
		if err != nil {
			return "", err
		}
		paths = append(paths, info.Path)
	}
	if len(paths) == 0 {
		return "", errors.New("no FIDO2 devices found")
	}
	if len(paths) != 1 {
		return "", errors.New("multiple FIDO2 devices found, please remove all but one")
	}
	transport, err := directhid.Open(ctx, paths[0])
	if err != nil {
		return "", err
	}
	device, err := authenticator.New(ctx, transport)
	if err != nil {
		transport.Close()
		return "", err
	}
	defer device.Close()

	var pinUvAuthToken []byte
	options := map[protocol.Option]bool{protocol.OptionResidentKeys: false}
	if pin == "" {
		options[protocol.OptionUserVerification] = true
	} else {
		pinUvAuthToken, err = device.GetPinUvAuthTokenUsingPIN(
			ctx,
			pin,
			protocol.PermissionMakeCredential,
			rpID,
		)
		if err != nil {
			return "", err
		}
		defer clear(pinUvAuthToken)
	}

	result, err := device.MakeCredential(
		ctx,
		pinUvAuthToken,
		nil,
		credential.PublicKeyCredentialRpEntity{ID: rpID},
		credential.PublicKeyCredentialUserEntity{
			// These are not used for non-resident credentials, but CTAP requires them.
			ID:   []byte{0},
			Name: label,
		},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretInputs: &webauthn.CreateHMACSecretInputs{
				HMACCreateSecret: true,
			},
		},
		options,
		0,
		nil,
	)
	if err != nil {
		return "", err
	}

	var identityData []byte
	identityData = ctap2cbor.AppendUint(identityData, 1)
	identityData = ctap2cbor.AppendBytes(identityData, result.AuthData.AttestedCredentialData.CredentialID)
	identityData = ctap2cbor.AppendString(identityData, rpID)
	identityData = ctap2cbor.AppendArray(identityData, "usb")
	return plugin.EncodeIdentity("fido2prf", identityData), nil
}

type Identity struct {
	credentialID []byte
	relyingParty string
	transports   []string

	getPIN func() (string, error)
}

const label = "age-encryption.org/fido2prf"

func (i *Identity) assert(nonce []byte) ([]byte, error) {
	ctx := context.Background()
	deviceFound := false
	for info, err := range directhid.Devices(ctx) {
		if err != nil {
			return nil, err
		}
		deviceFound = true

		transport, err := directhid.Open(ctx, info.Path)
		if err != nil {
			return nil, err
		}
		device, err := authenticator.New(ctx, transport)
		if err != nil {
			transport.Close()
			return nil, err
		}

		credentialDescriptor := credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   i.credentialID,
		}

		// First probe to check if the credential ID matches the device, before
		// requiring user interaction.
		var assertion protocol.AuthenticatorGetAssertionResponse
		for assertion, err = range device.GetAssertion(
			ctx,
			nil,
			i.relyingParty,
			nil,
			[]credential.PublicKeyCredentialDescriptor{credentialDescriptor},
			nil,
			map[protocol.Option]bool{protocol.OptionUserPresence: false},
		) {
			break
		}
		if err != nil {
			var ctapErr *ctaptransport.CTAPError
			if errors.As(err, &ctapErr) && ctapErr.StatusCode == ctaptransport.CTAP2_ERR_NO_CREDENTIALS {
				device.Close()
				continue
			}
			device.Close()
			return nil, err
		}

		salts := hmacSecretSalt(nonce)
		extensions := &webauthn.GetAuthenticationExtensionsClientInputs{
			GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{
					Salt1: salts[:32],
					Salt2: salts[32:],
				},
			},
		}

		var pinUvAuthToken []byte
		var options map[protocol.Option]bool
		cachedInfo, _ := device.GetInfoCached()
		if cachedInfo.Options[protocol.OptionUserVerification] {
			options = map[protocol.Option]bool{protocol.OptionUserVerification: true}
		} else {
			pin, err := i.getPIN()
			if err != nil {
				device.Close()
				return nil, err
			}
			pinUvAuthToken, err = device.GetPinUvAuthTokenUsingPIN(
				ctx,
				pin,
				protocol.PermissionGetAssertion,
				i.relyingParty,
			)
			if err != nil {
				device.Close()
				return nil, err
			}
			defer clear(pinUvAuthToken)
		}

		for assertion, err = range device.GetAssertion(
			ctx,
			pinUvAuthToken,
			i.relyingParty,
			nil,
			[]credential.PublicKeyCredentialDescriptor{credentialDescriptor},
			extensions,
			options,
		) {
			break
		}
		if err != nil {
			device.Close()
			return nil, err
		}

		output := assertion.ExtensionOutputs.GetHMACSecretOutputs.HMACGetSecret
		secret := make([]byte, 0, 64)
		secret = append(secret, output.Output1...)
		secret = append(secret, output.Output2...)
		clear(output.Output1)
		clear(output.Output2)
		device.Close()
		return secret, nil
	}
	if !deviceFound {
		return nil, errors.New("no FIDO2 devices found")
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
		clear(secret)
		fileKey, err := aeadDecrypt(key, 16, stanza.Body)
		clear(key)
		if err != nil {
			continue
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

// WrapWithLabels implements [age.RecipientWithLabels], returning a single
// "postquantum" label. This allows Identity to be mixed with other post-quantum
// recipients without triggering errors.
func (i *Identity) WrapWithLabels(fileKey []byte) ([]*age.Stanza, []string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	secret, err := i.assert(nonce)
	if err != nil {
		return nil, nil, err
	}
	key := hkdf.Extract(sha256.New, secret, []byte(label))
	clear(secret)
	ciphertext, err := aeadEncrypt(key, fileKey)
	clear(key)
	if err != nil {
		return nil, nil, err
	}
	return []*age.Stanza{{
		Type: label,
		Args: []string{base64.RawStdEncoding.Strict().EncodeToString(nonce)},
		Body: ciphertext,
	}}, []string{"postquantum"}, nil
}

func (i *Identity) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	s, _, err := i.WrapWithLabels(fileKey)
	return s, err
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
