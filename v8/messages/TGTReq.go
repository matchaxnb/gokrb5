package messages

import (
	"github.com/matchaxnb/gokrb5/v8/types"
)

// TGTReq implements Kerberos user2user KRB_TGT_REQ: https://datatracker.ietf.org/doc/html/draft-ietf-cat-user2user-02#section-2
//
//	KERB-TGT-REQUEST ::= SEQUENCE {
//		pvno[0]			INTEGER,
//		msg-type[1]		INTEGER,
//		server-name[2]	PrincipalName OPTIONAL,
//		realm[3]		Realm OPTIONAL
//	}
type TGTReq struct {
	// RFC 4120 Section 5.2.4
	// also TKT-VNO or AUTHENTICATOR-VNO, this recurring field is always
	// 	the constant integer 5. There is no easy way to make this field
	// 	into a useful protocol version number, so its value is fixed.
	PVNO int `asn1:"explicit,tag:0"`
	// RFC 4120 Section 5.2.4
	// msg-type
	// 	this integer field is usually identical to the application tag
	// 	number of the containing message type.
	// For a TGT request, this field is always KRB_TGT_REQ (16).
	MsgType int `asn1:"explicit,tag:1"`
	// server-name - this field optionally contains the name
	// 	of the server. If the client application doesn't
	// 	know the server name this can be left blank and
	// 	the server application will pick the appropriate
	// 	server credentials.
	ServerName types.PrincipalName `asn1:"explicit,optional,tag:2"`
	// realm - this field optionally contains the realm
	// 	of the server. If the client application doesn't
	// 	know the server realm this can be left blank and
	// 	the server application will pick the appropriate
	// 	server credentials.
	Realm string `asn1:"generalstring,explicit,optional,tag:3"`
}
