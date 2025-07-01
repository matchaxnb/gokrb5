package spnego

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/matchaxnb/gokrb5/v8/asn1tools"
	"github.com/matchaxnb/gokrb5/v8/client"
	"github.com/matchaxnb/gokrb5/v8/gssapi"
	"github.com/matchaxnb/gokrb5/v8/iana/chksumtype"
	"github.com/matchaxnb/gokrb5/v8/iana/flags"
	"github.com/matchaxnb/gokrb5/v8/iana/msgtype"
	"github.com/matchaxnb/gokrb5/v8/krberror"
	"github.com/matchaxnb/gokrb5/v8/messages"
	"github.com/matchaxnb/gokrb5/v8/service"
	"github.com/matchaxnb/gokrb5/v8/types"
)

// GSSAPI KRB5 MechToken IDs.
const (
	TOK_ID_KRB_AP_REQ  = "0100"
	TOK_ID_KRB_AP_REP  = "0200"
	TOK_ID_KRB_TGT_REQ = "0400"
	TOK_ID_KRB_TGT_REP = "0401"
	TOK_ID_KRB_ERROR   = "0300"
)

// KRB5Token context token implementation for GSSAPI.
type KRB5Token struct {
	OID      asn1.ObjectIdentifier
	tokID    []byte
	APReq    messages.APReq
	APRep    messages.APRep
	TGTReq   messages.TGTReq
	TGTRep   messages.TGTRep
	KRBError messages.KRBError
	settings *service.Settings
	context  context.Context
}

// Marshal a KRB5Token into a slice of bytes.
func (m *KRB5Token) Marshal() ([]byte, error) {
	// Create the header
	b, _ := asn1.Marshal(m.OID)
	b = append(b, m.tokID...)
	var tb []byte
	var err error
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		tb, err = m.APReq.Marshal()
		if err != nil {
			return []byte{}, fmt.Errorf("error marshalling AP_REQ for MechToken: %v", err)
		}
	case TOK_ID_KRB_AP_REP:
		return []byte{}, errors.New("marshal of AP_REP GSSAPI MechToken not supported by gokrb5")
	case TOK_ID_KRB_TGT_REQ:
		tb, err = asn1.Marshal(m.TGTReq)
		if err != nil {
			return []byte{}, fmt.Errorf("error marshalling TGT_REQ for MechToken: %v", err)
		}
	case TOK_ID_KRB_TGT_REP:
		tb, err = m.TGTRep.Marshal()
		if err != nil {
			return []byte{}, fmt.Errorf("error marshalling TGT_REP for MechToken: %v", err)
		}
	case TOK_ID_KRB_ERROR:
		return []byte{}, errors.New("marshal of KRB_ERROR GSSAPI MechToken not supported by gokrb5")
	}
	if err != nil {
		return []byte{}, fmt.Errorf("error mashalling kerberos message within mech token: %v", err)
	}
	b = append(b, tb...)
	return asn1tools.AddASNAppTag(b, 0), nil
}

// Unmarshal a KRB5Token.
func (m *KRB5Token) Unmarshal(b []byte) error {
	var oid asn1.ObjectIdentifier
	r, err := asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
	if err != nil {
		return fmt.Errorf("error unmarshalling KRB5Token OID: %v", err)
	}
	if !oid.Equal(gssapi.OIDKRB5.OID()) && !oid.Equal(gssapi.OIDKRB5User2User.OID()) {
		return fmt.Errorf("error unmarshalling KRB5Token, OID is %s not %s or %s", oid.String(), gssapi.OIDKRB5.OID().String(), gssapi.OIDKRB5User2User.OID().String())
	}
	m.OID = oid
	if len(r) < 2 {
		return fmt.Errorf("krb5token too short")
	}
	m.tokID = r[0:2]
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		var a messages.APReq
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REQ: %v", err)
		}
		m.APReq = a
	case TOK_ID_KRB_AP_REP:
		var a messages.APRep
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REP: %v", err)
		}
		m.APRep = a
	case TOK_ID_KRB_TGT_REQ:
		var a messages.TGTReq
		_, err := asn1.Unmarshal(r[2:], &a)
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token TGT_REQ: %v", err)
		}
		m.TGTReq = a
	case TOK_ID_KRB_TGT_REP:
		var a messages.TGTRep
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token TGT_REP: %v", err)
		}
		m.TGTRep = a
	case TOK_ID_KRB_ERROR:
		var a messages.KRBError
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token KRBError: %v", err)
		}
		m.KRBError = a
	}
	return nil
}

// Verify a KRB5Token.
func (m *KRB5Token) Verify() (bool, gssapi.Status) {
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		ok, creds, err := service.VerifyAPREQ(&m.APReq, m.settings)
		if err != nil {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}
		if !ok {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveCredential, Message: "KRB5_AP_REQ token not valid"}
		}
		m.context = context.Background()
		m.context = context.WithValue(m.context, ctxCredentials, creds)
		return true, gssapi.Status{Code: gssapi.StatusComplete}
	case TOK_ID_KRB_AP_REP:
		// Client side
		// TODO how to verify the AP_REP - not yet implemented
		return false, gssapi.Status{Code: gssapi.StatusFailure, Message: "verifying an AP_REP is not currently supported by gokrb5"}
	case TOK_ID_KRB_TGT_REQ:
		// https://datatracker.ietf.org/doc/html/draft-ietf-cat-user2user-02#section-2
		// specifies no verification for TGT_REQ
		return true, gssapi.Status{Code: gssapi.StatusContinueNeeded}
	case TOK_ID_KRB_TGT_REP:
		// https://datatracker.ietf.org/doc/html/draft-ietf-cat-user2user-02#section-2
		// specifies no verification for TGT_REP
		return true, gssapi.Status{Code: gssapi.StatusContinueNeeded}
	case TOK_ID_KRB_ERROR:
		if m.KRBError.MsgType != msgtype.KRB_ERROR {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "KRB5_Error token not valid"}
		}
		return true, gssapi.Status{Code: gssapi.StatusUnavailable}
	}
	return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "unknown TOK_ID in KRB5 token"}
}

// IsAPReq tests if the MechToken contains an AP_REQ.
func (m *KRB5Token) IsAPReq() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REQ {
		return true
	}
	return false
}

// IsAPRep tests if the MechToken contains an AP_REP.
func (m *KRB5Token) IsAPRep() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REP {
		return true
	}
	return false
}

// IsTGTReq tests if the MechToken contains an TGT_REQ.
func (m *KRB5Token) IsTGTReq() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_TGT_REQ {
		return true
	}
	return false
}

// IsTGTRep tests if the MechToken contains an TGT_REP.
func (m *KRB5Token) IsTGTRep() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_TGT_REP {
		return true
	}
	return false
}

// IsKRBError tests if the MechToken contains an KRB_ERROR.
func (m *KRB5Token) IsKRBError() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_ERROR {
		return true
	}
	return false
}

// Context returns the KRB5 token's context which will contain any verify user identity information.
func (m *KRB5Token) Context() context.Context {
	return m.context
}

// NewKRB5TokenAPREQ creates a new KRB5 token with AP_REQ
func NewKRB5TokenAPREQ(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, GSSAPIFlags []int, APOptions []int) (KRB5Token, error) {
	// TODO consider providing the SPN rather than the specific tkt and key and get these from the krb client.
	var m KRB5Token
	m.OID = gssapi.OIDKRB5.OID()
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
	m.tokID = tb

	auth, err := krb5TokenAuthenticator(cl.Credentials.Realm(), cl.Credentials.CName(), GSSAPIFlags)
	if err != nil {
		return m, err
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		auth,
	)
	if err != nil {
		return m, err
	}
	for _, o := range APOptions {
		types.SetFlag(&APReq.APOptions, o)
	}
	m.APReq = APReq
	return m, nil
}

// NewKRB5TokenTGTREQ creates a new KRB5 token with TGT_REQ.
// Both serverName and realm are optional.
// See https://datatracker.ietf.org/doc/html/draft-ietf-cat-user2user-02#section-2
// for more information on these fields.
func NewKRB5TokenTGTREQ(serverName types.PrincipalName, realm string) (KRB5Token, error) {
	var m KRB5Token
	m.OID = gssapi.OIDKRB5User2User.OID()
	tb, _ := hex.DecodeString(TOK_ID_KRB_TGT_REQ)
	m.tokID = tb

	TGTReq := messages.TGTReq{
		PVNO:       5,
		MsgType:    msgtype.KRB_TGT_REQ,
		ServerName: serverName,
		Realm:      realm,
	}
	m.TGTReq = TGTReq
	return m, nil
}

// NewKRB5TokenUser2UserAPREQ creates a new KRB5 token with AP_REQ for user-to-user authentication.
func NewKRB5TokenUser2UserAPREQ(realm string, cname types.PrincipalName, tkt messages.Ticket, sessionKey types.EncryptionKey) (KRB5Token, error) {
	var m KRB5Token
	m.OID = gssapi.OIDKRB5User2User.OID()
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
	m.tokID = tb
	apREQFlags := []int{
		// RFC 4120 Section 3.7
		// When contacting the server using a ticket obtained for user-to-user
		// authentication (message 3 in the table above), the client MUST
		// specify the USE-SESSION-KEY flag in the ap-options field. This tells
		// the application server to use the session key associated with its TGT
		// to decrypt the server ticket provided in the application request.
		flags.APOptionUseSessionKey,
		// RFC 4120 Section 3.2.4
		// Typically, a client’s request will include both the authentication
		// information and its initial request in the same message, and the
		// server need not explicitly reply to the KRB_AP_REQ. However, if
		// mutual authentication (authenticating not only the client to the
		// server, but also the server to the client) is being performed, the
		// KRB_AP_REQ message will have MUTUAL-REQUIRED set in its ap-options
		// field, and a KRB_AP_REP message is required in response.
		flags.APOptionMutualRequired,
	}
	gssFlags := []int{
		// Require mutual authentication
		gssapi.ContextFlagMutual,
		// Require confidentiality (encryption)
		gssapi.ContextFlagConf,
		// Require integrity (checksumming)
		gssapi.ContextFlagInteg,
	}
	auth, err := krb5TokenAuthenticator(realm, cname, gssFlags)
	if err != nil {
		return m, err
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		auth,
	)
	if err != nil {
		return m, err
	}
	for _, o := range apREQFlags {
		types.SetFlag(&APReq.APOptions, o)
	}
	m.APReq = APReq
	return m, nil
}

// krb5TokenAuthenticator creates a new kerberos authenticator for kerberos MechToken
func krb5TokenAuthenticator(realm string, cname types.PrincipalName, flags []int) (types.Authenticator, error) {
	//RFC 4121 Section 4.1.1
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		return auth, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  newAuthenticatorChksum(flags),
	}
	return auth, nil
}

// Create new authenticator checksum for kerberos MechToken
func newAuthenticatorChksum(flags []int) []byte {
	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[:4], 16)
	for _, i := range flags {
		if i == gssapi.ContextFlagDeleg {
			x := make([]byte, 28-len(a))
			a = append(a, x...)
		}
		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i)
		binary.LittleEndian.PutUint32(a[20:24], f)
	}
	return a
}
