package messages

import (
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/matchaxnb/gokrb5/v8/iana"
	"github.com/matchaxnb/gokrb5/v8/iana/msgtype"
	"github.com/matchaxnb/gokrb5/v8/iana/nametype"
	"github.com/matchaxnb/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestMarshalTGTReqRoundtrip(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledKRB5tgt_req)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	var a TGTReq
	_, err = asn1.Unmarshal(b, &a)
	if err != nil {
		t.Fatalf("Unmarshal of TGTReq errored: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "TGTReq PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGT_REQ, a.MsgType, "TGTReq MsgType not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ServerName.NameString, "TGTReq ServerName NameString not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ServerName.NameType, "TGTReq ServerName NameType not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "TGTReq Realm not as expected")

	mb, err := asn1.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal of ticket errored: %v", err)
	}
	assert.Equal(t, b, mb, "Marshal bytes of TGTReq not as expected")
}
