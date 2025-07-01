package gssapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/matchaxnb/gokrb5/v8/iana/keyusage"
	"github.com/matchaxnb/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

const (
	// What a kerberized server might send
	testChallengeFromAcceptor = "050401ff000c000000000000575e85d601010000853b728d5268525a1386c19f"
	// What an initiator client could reply
	testChallengeReplyFromInitiator = "050400ff000c000000000000000000000101000079a033510b6f127212242b97"
	// session key used to sign the tokens above
	sessionKey     = "14f9bde6b50ec508201a97f74c4e5bd3"
	sessionKeyType = 17

	acceptorSeal  = keyusage.GSSAPI_ACCEPTOR_SEAL
	initiatorSeal = keyusage.GSSAPI_INITIATOR_SEAL
)

func getSessionKey() types.EncryptionKey {
	key, _ := hex.DecodeString(sessionKey)
	return types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: key,
	}
}

func getChallengeReference() *WrapToken {
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	return &WrapToken{
		Flags:     0x01,
		EC:        12,
		RRC:       0,
		SndSeqNum: binary.BigEndian.Uint64(challenge[8:16]),
		Payload:   []byte{0x01, 0x01, 0x00, 0x00},
		CheckSum:  challenge[20:32],
	}
}

func getChallengeReferenceNoChksum() *WrapToken {
	c := getChallengeReference()
	c.CheckSum = nil
	return c
}

func getResponseReference() *WrapToken {
	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	return &WrapToken{
		Flags:     0x00,
		EC:        12,
		RRC:       0,
		SndSeqNum: 0,
		Payload:   []byte{0x01, 0x01, 0x00, 0x00},
		CheckSum:  response[20:32],
	}
}

func getResponseReferenceNoChkSum() *WrapToken {
	r := getResponseReference()
	r.CheckSum = nil
	return r
}

func TestUnmarshal_Challenge(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	err := wt.Unmarshal(challenge, true)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, getChallengeReference(), &wt, "Token not decoded as expected.")
}

func TestUnmarshalFailure_Challenge(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	err := wt.Unmarshal(challenge, false)
	assert.NotNil(t, err, "Expected error did not occur: a message from the acceptor cannot be expected to be sent from the initiator.")
	assert.Nil(t, wt.Payload, "Token fields should not have been initialised")
	assert.Nil(t, wt.CheckSum, "Token fields should not have been initialised")
	assert.Equal(t, byte(0x00), wt.Flags, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.EC, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.RRC, "Token fields should not have been initialised")
	assert.Equal(t, uint64(0), wt.SndSeqNum, "Token fields should not have been initialised")
}

func TestUnmarshal_ChallengeReply(t *testing.T) {
	t.Parallel()
	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	var wt WrapToken
	err := wt.Unmarshal(response, false)
	assert.Nil(t, err, "Unexpected error occurred.")
	assert.Equal(t, getResponseReference(), &wt, "Token not decoded as expected.")
}

func TestUnmarshalFailure_ChallengeReply(t *testing.T) {
	t.Parallel()
	response, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	var wt WrapToken
	err := wt.Unmarshal(response, true)
	assert.NotNil(t, err, "Expected error did not occur: a message from the initiator cannot be expected to be sent from the acceptor.")
	assert.Nil(t, wt.Payload, "Token fields should not have been initialised")
	assert.Nil(t, wt.CheckSum, "Token fields should not have been initialised")
	assert.Equal(t, byte(0x00), wt.Flags, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.EC, "Token fields should not have been initialised")
	assert.Equal(t, uint16(0), wt.RRC, "Token fields should not have been initialised")
	assert.Equal(t, uint64(0), wt.SndSeqNum, "Token fields should not have been initialised")
}

func Test_Marshal_Unmarshal_Sealed_Roundtrip(t *testing.T) {
	wt := WrapToken{
		Flags:     byte(WrapTokenFlagSealed),
		EC:        0,
		RRC:       28,
		SndSeqNum: 0,
		Payload:   []byte("Hello world"),
	}
	sk := getSessionKey()
	err := wt.EncryptPayload(sk, initiatorSeal)
	assert.NoError(t, err, "Error encrypting payload")
	b, err := wt.Marshal()
	assert.NoError(t, err, "Error marshalling token")

	var wt2 WrapToken
	err = wt2.Unmarshal(b, false)
	assert.NoError(t, err, "Error unmarshalling token")
	err = wt2.DecryptPayload(sk, initiatorSeal)
	assert.NoError(t, err, "Error decrypting payload")
	assert.EqualValues(t, "Hello world", wt2.Payload, "Payload roundtrip failed")
	assert.Equal(t, wt.Flags, wt2.Flags, "Flags roundtrip failed")
	assert.Equal(t, wt.EC, wt2.EC, "EC roundtrip failed")
	assert.Equal(t, wt.RRC, wt2.RRC, "RRC roundtrip failed")
	assert.Equal(t, wt.SndSeqNum, wt2.SndSeqNum, "SendSeqNum roundtrip failed")
}

func TestChallengeChecksumVerification(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	wt.Unmarshal(challenge, true)
	challengeOk, cErr := wt.Verify(getSessionKey(), acceptorSeal)
	assert.Nil(t, cErr, "Error occurred during checksum verification.")
	assert.True(t, challengeOk, "Checksum verification failed.")
}

func TestResponseChecksumVerification(t *testing.T) {
	t.Parallel()
	reply, _ := hex.DecodeString(testChallengeReplyFromInitiator)
	var wt WrapToken
	wt.Unmarshal(reply, false)
	replyOk, rErr := wt.Verify(getSessionKey(), initiatorSeal)
	assert.Nil(t, rErr, "Error occurred during checksum verification.")
	assert.True(t, replyOk, "Checksum verification failed.")
}

func TestChecksumVerificationFailure(t *testing.T) {
	t.Parallel()
	challenge, _ := hex.DecodeString(testChallengeFromAcceptor)
	var wt WrapToken
	wt.Unmarshal(challenge, true)

	// Test a failure with the correct key but wrong keyusage:
	challengeOk, cErr := wt.Verify(getSessionKey(), initiatorSeal)
	assert.NotNil(t, cErr, "Expected error did not occur.")
	assert.False(t, challengeOk, "Checksum verification succeeded when it should have failed.")

	wrongKeyVal, _ := hex.DecodeString("14f9bde6b50ec508201a97f74c4effff")
	badKey := types.EncryptionKey{
		KeyType:  sessionKeyType,
		KeyValue: wrongKeyVal,
	}
	// Test a failure with the wrong key but correct keyusage:
	wrongKeyOk, wkErr := wt.Verify(badKey, acceptorSeal)
	assert.NotNil(t, wkErr, "Expected error did not occur.")
	assert.False(t, wrongKeyOk, "Checksum verification succeeded when it should have failed.")
}

func TestMarshal_Challenge(t *testing.T) {
	t.Parallel()
	bytes, _ := getChallengeReference().Marshal()
	assert.Equal(t, testChallengeFromAcceptor, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_ChallengeReply(t *testing.T) {
	t.Parallel()
	bytes, _ := getResponseReference().Marshal()
	assert.Equal(t, testChallengeReplyFromInitiator, hex.EncodeToString(bytes),
		"Marshalling did not yield the expected result.")
}

func TestMarshal_Failures(t *testing.T) {
	t.Parallel()
	noChkSum := getResponseReferenceNoChkSum()
	chkBytes, chkErr := noChkSum.Marshal()
	assert.Nil(t, chkBytes, "No bytes should be returned.")
	assert.NotNil(t, chkErr, "Expected an error as no checksum was set")

	noPayload := getResponseReference()
	noPayload.Payload = nil
	pldBytes, pldErr := noPayload.Marshal()
	assert.Nil(t, pldBytes, "No bytes should be returned.")
	assert.NotNil(t, pldErr, "Expected an error as no checksum was set")
}

func TestNewInitiatorTokenSignatureAndMarshalling(t *testing.T) {
	t.Parallel()
	token, tErr := NewInitiatorWrapToken([]byte{0x01, 0x01, 0x00, 0x00}, getSessionKey())
	assert.Nil(t, tErr, "Unexpected error.")
	assert.Equal(t, getResponseReference(), token, "Token failed to be marshalled to the expected bytes.")
}

func Test_rotateRight(t *testing.T) {
	t.Parallel()
	t.Run("when n is < len(v)", func(t *testing.T) {
		t.Parallel()
		v := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		v = rotateRight(v, 3)
		if equal := bytes.Equal(v, []byte{0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05}); !equal {
			t.Error("rotateRight failed")
		}
	})
	t.Run("when n is > len(v)", func(t *testing.T) {
		t.Parallel()
		v := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		v = rotateRight(v, 10)
		if equal := bytes.Equal(v, []byte{0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}); !equal {
			t.Error("rotateRight failed")
		}
	})
}

func Test_rotateLeft(t *testing.T) {
	t.Parallel()
	t.Run("when n is < len(v)", func(t *testing.T) {
		t.Parallel()
		v := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		v = rotateLeft(v, 3)
		if equal := bytes.Equal(v, []byte{0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03}); !equal {
			t.Error("rotateLeft failed")
		}
	})
	t.Run("when n is > len(v)", func(t *testing.T) {
		t.Parallel()
		v := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		v = rotateLeft(v, 10)
		if equal := bytes.Equal(v, []byte{0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02}); !equal {
			t.Error("rotateLeft failed")
		}
	})
}
