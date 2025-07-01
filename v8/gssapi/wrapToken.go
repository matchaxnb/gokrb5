package gssapi

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/matchaxnb/gokrb5/v8/crypto"
	"github.com/matchaxnb/gokrb5/v8/iana/keyusage"
	"github.com/matchaxnb/gokrb5/v8/types"
)

// RFC 4121, section 4.2.6.2

const (
	// HdrLen is the length of the Wrap Token's header
	HdrLen = 16
	// FillerByte is a filler in the WrapToken structure
	FillerByte byte = 0xFF
)

// RFC 4121, section 4.2.2

const (
	// WrapTokenFlagSentByAcceptor - this flag indicates the sender is the context acceptor.  When not set, it indicates the sender is the context initiator
	WrapTokenFlagSentByAcceptor = 1 << iota
	// WrapTokenFlagSealed - this flag indicates confidentiality is provided for.  It SHALL NOT be set in MIC tokens
	WrapTokenFlagSealed
	// WrapTokenFlagAcceptorSubkey - a subkey asserted by the context acceptor is used to protect the message
	WrapTokenFlagAcceptorSubkey
)

// WrapToken represents a GSS API Wrap token, as defined in RFC 4121.
// It contains the header fields, the payload and the checksum, and provides
// the logic for converting to/from bytes plus computing and verifying checksums
type WrapToken struct {
	// const GSS Token ID: 0x0504
	Flags byte // contains three flags: acceptor, sealed, acceptor subkey
	// const Filler: 0xFF
	EC        uint16 // checksum length. big-endian
	RRC       uint16 // right rotation count. big-endian
	SndSeqNum uint64 // sender's sequence number. big-endian
	Payload   []byte // your data! :)
	CheckSum  []byte // authenticated checksum of { payload | header }
}

// Return the 2 bytes identifying a GSS API Wrap token
func getGssWrapTokenId() *[2]byte {
	return &[2]byte{0x05, 0x04}
}

// Build a header for the WrapToken, overriding the token
// EC and RRC values with those provided.
func (wt *WrapToken) getWrapTokenHeader(ec, rrc uint16) []byte {
	header := make([]byte, HdrLen)
	copy(header[0:], getGssWrapTokenId()[:])
	header[2] = wt.Flags
	header[3] = FillerByte
	binary.BigEndian.PutUint16(header[4:6], ec)
	binary.BigEndian.PutUint16(header[6:8], rrc)
	binary.BigEndian.PutUint64(header[8:16], wt.SndSeqNum)
	return header
}

// Marshal the WrapToken into a byte slice.
// The payload should have been set and the checksum computed, otherwise an error is returned.
func (wt *WrapToken) Marshal() ([]byte, error) {
	if wt.CheckSum == nil {
		return nil, errors.New("checksum has not been set")
	}
	if wt.Payload == nil {
		return nil, errors.New("payload has not been set")
	}

	bytes := wt.getWrapTokenHeader(wt.EC, wt.RRC)
	bytes = append(bytes, wt.Payload...)
	bytes = append(bytes, wt.CheckSum...)
	return bytes, nil
}

// EncryptPayload encrypts the payload of this token using the passed key and key usage.
// It requires the payload to have been set, and the checksum to not have been computed,
// and the WrapTokenFlagSealed flag to be set in the Flags field.
func (wt *WrapToken) EncryptPayload(key types.EncryptionKey, keyUsage uint32) error {
	if wt.Payload == nil {
		return errors.New("payload has not been set")
	}
	if wt.CheckSum != nil {
		return errors.New("checksum has already been computed")
	}
	if wt.Flags&WrapTokenFlagSealed == 0 {
		return errors.New("token is not sealed")
	}

	// RFC 4121 Section 4.2.4
	// In Wrap tokens that provide for confidentiality, the first 16 octets
	// of the Wrap token (the "header", as defined in section 4.2.6), SHALL
	// be appended to the plaintext data before encryption. Filler octets
	// MAY be inserted between the plaintext data and the "header".
	// The resulting Wrap token is {"header" | encrypt(plaintext-data | filler | "header")},
	// where encrypt() is the encryption operation (which provides for integrity protection)
	// defined in the crypto profile [RFC3961], and the RRC field (as
	// defined in section 4.2.5) in the to-be-encrypted header contains the
	// hex value 00 00.
	hdr := wt.getWrapTokenHeader(wt.EC, 0) // RRC is 0
	filler := bytes.Repeat([]byte{0x00}, int(wt.EC))
	// plaintext-data | filler | "header"
	payload := append(append(wt.Payload, filler...), hdr...)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return err
	}
	_, ct, err := encType.EncryptMessage(key.KeyValue, payload, keyUsage)
	if err != nil {
		return err
	}
	// Right-rotate the ciphertext and integrity hash by RRC bits
	// RFC 4121 Section 4.2.5
	rotCt := rotateRight(ct, int(wt.RRC))

	// Set the payload and checksum again for the purposes of marshaling,
	// though they don't really map to the fields in the token anymore.
	// Set the checksum to the last checksum-size of bytes of the rotated ciphertext
	checksumLen := encType.GetHMACBitLength() / 8
	wt.Payload = rotCt[:len(rotCt)-checksumLen]
	wt.CheckSum = rotCt[len(rotCt)-checksumLen:]
	return nil
}

// SetCheckSum uses the passed encryption key and key usage to compute the checksum over the payload and
// the header, and sets the CheckSum field of this WrapToken.
// If the payload has not been set or the checksum has already been set, an error is returned.
// This function cannot be used when the WrapTokenFlagSealed flag is set, use EncryptPayload instead.
func (wt *WrapToken) SetCheckSum(key types.EncryptionKey, keyUsage uint32) error {
	if wt.Payload == nil {
		return errors.New("payload has not been set")
	}
	if wt.CheckSum != nil {
		return errors.New("checksum has already been computed")
	}
	if wt.Flags&WrapTokenFlagSealed == 1 {
		return errors.New("token is sealed, cannot set checksum, use EncryptPayload instead")
	}
	chkSum, cErr := wt.computeCheckSum(key, keyUsage)
	if cErr != nil {
		return cErr
	}
	wt.CheckSum = chkSum
	return nil
}

// ComputeCheckSum computes and returns the checksum of this token, computed using the passed key and key usage.
// Note: This will NOT update the struct's Checksum field.
func (wt *WrapToken) computeCheckSum(key types.EncryptionKey, keyUsage uint32) ([]byte, error) {
	if wt.Payload == nil {
		return nil, errors.New("cannot compute checksum with uninitialized payload")
	}
	// Build a slice containing { payload | header }
	checksumMe := make([]byte, HdrLen+len(wt.Payload))
	copy(checksumMe[0:], wt.Payload)
	copy(checksumMe[len(wt.Payload):], wt.getWrapTokenHeader(0, 0))

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	return encType.GetChecksumHash(key.KeyValue, checksumMe, keyUsage)
}

// Verify computes the token's checksum with the provided key and usage,
// and compares it to the checksum present in the token.
// In case of any failure, (false, Err) is returned, with Err an explanatory error.
func (wt *WrapToken) Verify(key types.EncryptionKey, keyUsage uint32) (bool, error) {
	if wt.Flags&WrapTokenFlagSealed == 1 {
		// Nothing to do for sealed tokens, the checksum is already verified by DecryptPayload,
		// and cannot be verified here without the confounder and trailing filler and header.
		return false, errors.New("token is sealed, cannot verify checksum, use DecryptPayload instead")
	}
	computed, cErr := wt.computeCheckSum(key, keyUsage)
	if cErr != nil {
		return false, cErr
	}
	if !hmac.Equal(computed, wt.CheckSum) {
		return false, fmt.Errorf(
			"checksum mismatch. Computed: %s, Contained in token: %s",
			hex.EncodeToString(computed), hex.EncodeToString(wt.CheckSum))
	}
	return true, nil
}

// Unmarshal bytes into the corresponding WrapToken.
// If expectFromAcceptor is true, we expect the token to have been emitted by the gss acceptor,
// and will check the according flag, returning an error if the token does not match the expectation.
// If the token is sealed, the payload will be set to the encrypted payload.
// Use DecryptPayload to decrypt it.
func (wt *WrapToken) Unmarshal(b []byte, expectFromAcceptor bool) error {
	// Check if we can read a whole header
	if len(b) < 16 {
		return errors.New("bytes shorter than header length")
	}
	// Is the Token ID correct?
	if !bytes.Equal(getGssWrapTokenId()[:], b[0:2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]),
			hex.EncodeToString(b[0:2]))
	}
	// Check the acceptor flag
	flags := b[2]
	isFromAcceptor := flags&WrapTokenFlagSentByAcceptor == 1
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	}
	// Check the filler byte
	if b[3] != FillerByte {
		return fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(b[3:4]))
	}
	checksumL := binary.BigEndian.Uint16(b[4:6])
	// Sanity check on the checksum length
	if int(checksumL) > len(b)-HdrLen {
		return fmt.Errorf("inconsistent checksum length: %d bytes to parse, checksum length is %d", len(b), checksumL)
	}

	wt.Flags = flags
	wt.EC = checksumL
	wt.RRC = binary.BigEndian.Uint16(b[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])
	if wt.Flags&WrapTokenFlagSealed == 0 {
		wt.Payload = b[HdrLen : len(b)-int(checksumL)]
		wt.CheckSum = b[len(b)-int(checksumL):]
	} else {
		// With a sealed token, the payload and checksum are rotated by RRC bits
		// Left-rotate the payload and checksum by RRC bits
		// RFC 4121 Section 4.2.5
		encryptedPayloadAndChecksum := rotateLeft(b[HdrLen:], int(wt.RRC))
		// We don't know the size of the checksum yet, as it depends on the encryption type,
		// so we just assign the payload.
		wt.Payload = encryptedPayloadAndChecksum
	}
	return nil
}

// DecryptPayload decrypts the payload of this token using the passed key and key usage.
// It requires the payload to have been set by unmarshaling the token. The checksum
// must not be set. The WrapTokenFlagSealed flag must be set in the Flags field.
// This function will not set the checksum field, as it has already been verified by the decryption process.
func (wt *WrapToken) DecryptPayload(key types.EncryptionKey, keyUsage uint32) error {
	if len(wt.Payload) == 0 {
		return errors.New("payload has not been set, use Unmarshal first")
	}
	if len(wt.CheckSum) != 0 {
		return errors.New("checksum has already been set")
	}
	if wt.Flags&WrapTokenFlagSealed == 0 {
		return errors.New("token is not sealed")
	}

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return err
	}

	// Decrypt the payload. This also verifies the integrity of the message.
	decryptedPayload, err := encType.DecryptMessage(key.KeyValue, wt.Payload, keyUsage)
	if err != nil {
		return err
	}

	// The decrypted payload should be of the form { plaintext-data | filler | "header" }
	// Extract the plaintext-data and return it
	plaintextLen := len(decryptedPayload) - int(wt.EC) - HdrLen
	if plaintextLen < 0 {
		return fmt.Errorf("invalid decrypted data, trailing filler and header are larger than the decrypted data")
	}
	wt.Payload = decryptedPayload[:plaintextLen]
	// Note: we do not assign the checksum, because it has already been verified by DecryptMessage,
	// and it cannot be verified again without access to the confounder and trailing filler and header.
	return nil
}

// rotateRight rotates the byte slice s to the right by n bytes.
func rotateRight(s []byte, n int) []byte {
	if n == 0 {
		return s
	}
	n = n % len(s)
	return append(s[len(s)-n:], s[:len(s)-n]...)
}

// rotateLeft rotates the byte slice s to the left by n bytes.
func rotateLeft(s []byte, n int) []byte {
	if n == 0 {
		return s
	}
	n = n % len(s)
	return append(s[n:], s[:n]...)
}

// NewInitiatorWrapToken builds a new initiator token (acceptor flag will be set to 0) and computes the authenticated checksum.
// Other flags are set to 0, and the RRC and sequence number are initialized to 0.
// Note that in certain circumstances you may need to provide a sequence number that has been defined earlier.
// This is currently not supported.
func NewInitiatorWrapToken(payload []byte, key types.EncryptionKey) (*WrapToken, error) {
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	token := WrapToken{
		Flags: 0x00, // all zeroed out (this is a token sent by the initiator)
		// Checksum size: length of output of the HMAC function, in bytes.
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 0,
		Payload:   payload,
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	return &token, nil
}
