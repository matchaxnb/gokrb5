package messages

import (
	"encoding/asn1"

	"github.com/matchaxnb/gokrb5/v8/iana/msgtype"
	"github.com/matchaxnb/gokrb5/v8/krberror"
	"github.com/matchaxnb/gokrb5/v8/types"
)

// TGTRep implements Keberos user2user KRB_TGT_REP: https://datatracker.ietf.org/doc/html/draft-ietf-cat-user2user-02#section-2
//
//	KERB-TGT-REPLY ::= SEQUENCE {
//		pvno[0]                         INTEGER,
//		msg-type[1]                     INTEGER,
//		ticket[2]                       Ticket,
//		server-name[4]                  PrincipalName OPTIONAL,
//	}
type TGTRep struct {
	// RFC 4120 Section 5.2.4
	// also TKT-VNO or AUTHENTICATOR-VNO, this recurring field is always
	// 	the constant integer 5. There is no easy way to make this field
	// 	into a useful protocol version number, so its value is fixed.
	PVNO int
	// RFC 4120 Section 5.2.4
	// msg-type
	// 	this integer field is usually identical to the application tag
	// 	number of the containing message type.
	// For a TGT response, this field is always KRB_TGT_REP (17).
	MsgType int
	// ticket - contains the TGT for the service specified
	// 	by the server name and realm passed by the client
	// 	or the default service.
	Ticket Ticket
	// server-name - server's principal name. If the client
	// 	does not supply the server name, the server will
	// 	return the name. This allows the client to
	// 	discover the server's principal name in situations
	// 	where it isn't known. However, if the client
	// 	doesn't know the server's principal name then
	// 	authentication is not mutual - any server can
	// 	respond to the client. The server realm is not
	// 	returned separately because it is in the ticket
	// 	structure.
	ServerName types.PrincipalName
}

type marshalTGTRep struct {
	PVNO    int `asn1:"explicit,tag:0"`
	MsgType int `asn1:"explicit,tag:1"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	Ticket     asn1.RawValue       `asn1:"explicit,tag:2"`
	ServerName types.PrincipalName `asn1:"explicit,tag:4,optional"`
}

func (k *TGTRep) Unmarshal(data []byte) error {
	var m marshalTGTRep
	_, err := asn1.Unmarshal(data, &m)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "unmarshal error of TGT_REP")
	}
	expectedMsgType := msgtype.KRB_TGT_REP
	if m.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_TGT_REP. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}
	k.PVNO = m.PVNO
	k.MsgType = m.MsgType
	k.ServerName = m.ServerName
	k.Ticket, err = unmarshalTicket(m.Ticket.Bytes)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "unmarshaling error of Ticket within TGT_REP")
	}
	return nil
}

func (k *TGTRep) Marshal() ([]byte, error) {
	m := marshalTGTRep{
		PVNO:       k.PVNO,
		MsgType:    k.MsgType,
		ServerName: k.ServerName,
	}
	b, err := k.Ticket.Marshal()
	if err != nil {
		return b, err
	}
	m.Ticket = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        2,
		Bytes:      b,
	}
	mk, err := asn1.Marshal(m)
	if err != nil {
		return mk, krberror.Errorf(err, krberror.EncodingError, "marshaling error of TGT_REP")
	}
	return mk, nil
}
