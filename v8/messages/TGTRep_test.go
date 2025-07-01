package messages

import (
	"encoding/hex"
	"testing"

	"github.com/matchaxnb/gokrb5/v8/iana"
	"github.com/matchaxnb/gokrb5/v8/iana/msgtype"
	"github.com/matchaxnb/gokrb5/v8/iana/nametype"
	"github.com/matchaxnb/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestMarshalTGTRepRoundtrip(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledKRB5tgt_rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	var a TGTRep
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal of TGTRep errored: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "TGTRep PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGT_REP, a.MsgType, "TGTRep MsgType not as expected")
	assert.NotNil(t, a.Ticket, "TGTRep Ticket is nil")
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO, "Ticket VNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName name string entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Ticket encPart etype not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO, "Ticket encPart KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Ticket.EncPart.Cipher, "Ticket encPart cipher not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ServerName.NameString, "TGTRep ServerName NameString not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ServerName.NameType, "TGTRep ServerName NameType not as expected")

	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal of ticket errored: %v", err)
	}
	assert.Equal(t, b, mb, "Marshal bytes of TGTRep not as expected")
}
