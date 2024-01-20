package ctap

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/tpc3/go-fido"
	"github.com/veraison/go-cose"
)

const AuthenticatorMakeCredentialCommandId uint8 = 0x01

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
type AuthenticatorMakeCredentialRequest struct {
	// Required
	ClientDataHash []byte `cbor:"1,keyasint"`
	// Required
	RP fido.PublicKeyCredentialRpEntity `cbor:"2,keyasint"`
	// Required
	User fido.PublicKeyCredentialUserEntity `cbor:"3,keyasint"`
	// Required
	PubKeyCredParams []fido.PublicKeyCredentialParameters `cbor:"4,keyasint"`
	// Optional
	ExcludeList []fido.PublicKeyCredentialDescriptor `cbor:"5,keyasint,omitempty"`
	// Optional
	Extensions map[string]interface{} `cbor:"6,keyasint,omitempty"`
	// Optional
	Options AuthenticatorMakeCredentialRequestOptions `cbor:"7,keyasint,omitempty"`
	// Optional
	PinUvAuthParam []byte `cbor:"8,keyasint,omitempty"`
	// Optional
	PinUvAuthProtocol uint `cbor:"9,keyasint,omitempty"`
	// Optional
	EnterpriseAttestation uint `cbor:"10,keyasint,omitempty"`
}

type AuthenticatorMakeCredentialRequestOptions struct {
	RK bool  `cbor:"rk,omitempty"`
	UP bool  `cbor:"up,omitempty"`
	UV *bool `cbor:"uv,omitempty"`
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
type AuthenticatorMakeCredentialResponse struct {
	// Required
	Fmt string `cbor:"1,keyasint"`
	// Required
	// Can be Decoded by AuthenticatorData.UnmarshalBinary()
	AuthData []byte `cbor:"2,keyasint"`
	// Required
	AttStmt cbor.RawMessage `cbor:"3,keyasint"`
	// Optional
	EpAtt bool `cbor:"4,keyasint,omitempty"`
	// Optional
	LargeBlobKey []byte `cbor:"5,keyasint,omitempty"`
}

const AuthenticatorGetAssertionCommandId uint8 = 0x02
const AuthenticatorGetNextAssertionCommandId uint8 = 0x08

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
type AuthenticatorGetAssertionRequest struct {
	// Required
	RPID string `cbor:"1,keyasint"`
	// Required
	ClientDataHash []byte `cbor:"2,keyasint"`
	// Optional
	AllowList []fido.PublicKeyCredentialDescriptor `cbor:"3,keyasint,omitempty"`
	// Optional
	Extensions map[string]interface{} `cbor:"4,keyasint,omitempty"`
	// Optional
	Options AuthenticatorGetAssertionRequestOptions `cbor:"5,keyasint,omitempty"`
	// Optional
	PinUvAuthParam []byte `cbor:"6,keyasint,omitempty"`
	// Optional
	PinUvAuthProtocol uint `cbor:"7,keyasint,omitempty"`
}

type AuthenticatorGetAssertionRequestOptions struct {
	UP bool  `cbor:"up,omitempty"`
	UV *bool `cbor:"uv,omitempty"`
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
type AuthenticatorGetAssertionResponse struct {
	// Required
	Credential fido.PublicKeyCredentialDescriptor `cbor:"1,keyasint"`
	// Required
	// Can be Decoded by AuthenticatorData.UnmarshalBinary()
	AuthData []byte `cbor:"2,keyasint"`
	// Required
	Signature []byte `cbor:"3,keyasint"`
	// Optional
	User fido.PublicKeyCredentialUserEntity `cbor:"4,keyasint,omitempty"`
	// Optional
	NumberOfCredentials int `cbor:"5,keyasint,omitempty"`
	// Optional
	UserSelected bool `cbor:"6,keyasint,omitempty"`
	// Optional
	LargeBlobKey []byte `cbor:"7,keyasint,omitempty"`
}

const AuthenticatorGetInfoCommandId uint8 = 0x04

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
type AuthenticatorGetInfoResponse struct {
	// Required
	Version []string `cbor:"1,keyasint"`
	// Optional
	Extensions []string `cbor:"2,keyasint,omitempty"`
	// Required
	AAGUID []byte `cbor:"3,keyasint"`
	// Optional
	Options map[AuthenticatorGetInfoResopnseOptionID]bool `cbor:"4,keyasint,omitempty"`
	// Optional
	MaxMsgSize uint `cbor:"5,keyasint,omitempty"`
	// Optional
	PinUvAuthProtocols []uint `cbor:"6,keyasint,omitempty"`
	// Optional
	MaxCredentialCountInList uint `cbor:"7,keyasint,omitempty"`
	// Optional
	MaxCredentialIdLength uint `cbor:"8,keyasint,omitempty"`
	// Optional
	Transports []string `cbor:"9,keyasint,omitempty"`
	// Optional
	Algorithms []fido.PublicKeyCredentialParameters `cbor:"10,keyasint,omitempty"`
	// Optional
	MaxSerializedLargeBlobArray uint `cbor:"11,keyasint,omitempty"`
	// Optional
	ForcePINChange bool `cbor:"12,keyasint,omitempty"`
	// Optional
	MinPINLength uint `cbor:"13,keyasint,omitempty"`
	// Optional
	FirmwareVersion uint `cbor:"14,keyasint,omitempty"`
	// Optional
	MaxCredBlobLength uint `cbor:"15,keyasint,omitempty"`
	// Optional
	MaxRPIDsForSetMinPINLength uint `cbor:"16,keyasint,omitempty"`
	// Optional
	PreferredPlatformUvAttempts uint `cbor:"17,keyasint,omitempty"`
	// Optional
	UvModality uint `cbor:"18,keyasint,omitempty"`
	// Optional
	Certifications map[any]any `cbor:"19,keyasint,omitempty"`
	// Optional
	RemainingDiscoverableCredentials uint `cbor:"20,keyasint,omitempty"`
	// Optional
	VendorPrototypeConfigCommands []uint `cbor:"21,keyasint,omitempty"`
	// WIP
}

func (i *AuthenticatorGetInfoResponse) IsOptionTrue(option AuthenticatorGetInfoResopnseOptionID) bool {
	opt, ok := i.Options[option]
	return ok && opt
}

type AuthenticatorCTAPVersion string

const (
	AuthenticatorCTAPVersion1       AuthenticatorCTAPVersion = "U2F_V2"
	AuthenticatorCTAPVersion2_0     AuthenticatorCTAPVersion = "FIDO_2_0"
	AuthenticatorCTAPVersion2_1_PRE AuthenticatorCTAPVersion = "FIDO_2_1_PRE"
	AuthenticatorCTAPVersion2_1     AuthenticatorCTAPVersion = "FIDO_2_1"
)

type AuthenticatorGetInfoResopnseOptionID string

const AuthenticatorClientPINCommandId uint8 = 0x06

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
type AuthenticatorClientPINRequest struct {
	// Optional
	PinUvAuthProtocol uint `cbor:"1,keyasint,omitempty"`
	// Required
	SubCommand AuthenticatorClientPINRequestSubCommand `cbor:"2,keyasint"`
	// Optional
	KeyAgreement *PinUvAuthProtocolKey `cbor:"3,keyasint,omitempty"`
	// Optional
	PinUvAuthParam []byte `cbor:"4,keyasint,omitempty"`
	// Optional
	NewPinEnc []byte `cbor:"5,keyasint,omitempty"`
	// Optional
	PinHashEnc []byte `cbor:"6,keyasint,omitempty"`
	// Optional
	Permissions PinUvAuthTokenPermission `cbor:"4,keyasint,omitempty"`
	// Optional
	RPID string `cbor:"10,keyasint,omitempty"`
}

type AuthenticatorClientPINRequestSubCommand uint

const (
	AuthenticatorClientPINRequestSubCommandGetPINRetries                            AuthenticatorClientPINRequestSubCommand = 0x01
	AuthenticatorClientPINRequestSubCommandGetKeyAgreement                          AuthenticatorClientPINRequestSubCommand = 0x02
	AuthenticatorClientPINRequestSubCommandSetPIN                                   AuthenticatorClientPINRequestSubCommand = 0x03
	AuthenticatorClientPINRequestSubCommandChangePIN                                AuthenticatorClientPINRequestSubCommand = 0x04
	AuthenticatorClientPINRequestSubCommandGetPINToken                              AuthenticatorClientPINRequestSubCommand = 0x05
	AuthenticatorClientPINRequestSubCommandGetPinUvAuthTokenUsingUvWithPermissions  AuthenticatorClientPINRequestSubCommand = 0x06
	AuthenticatorClientPINRequestSubCommandGetUVRetries                             AuthenticatorClientPINRequestSubCommand = 0x07
	AuthenticatorClientPINRequestSubCommandGetPinUvAuthTokenUsingPinWithPermissions AuthenticatorClientPINRequestSubCommand = 0x09
)

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#gettingPinUvAuthToken
type PinUvAuthTokenPermission uint

const (
	PinUvAuthTokenPermissionMakeCredential             PinUvAuthTokenPermission = 0x01
	PinUvAuthTokenPermissionGetAssertion               PinUvAuthTokenPermission = 0x02
	PinUvAuthTokenPermissionCredentialManagement       PinUvAuthTokenPermission = 0x04
	PinUvAuthTokenPermissionBioEnrollment              PinUvAuthTokenPermission = 0x08
	PinUvAuthTokenPermissionLargeBlobWrite             PinUvAuthTokenPermission = 0x10
	PinUvAuthTokenPermissionAuthenticatorConfiguration PinUvAuthTokenPermission = 0x20
)

type AuthenticatorClientPINRequestOptions struct {
	UP bool  `cbor:"up,omitempty"`
	UV *bool `cbor:"uv,omitempty"`
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
type AuthenticatorClientPINResponse struct {
	// Optional
	KeyAgreement *PinUvAuthProtocolKey `cbor:"1,keyasint,omitempty"`
	// Optional
	PinUvAuthToken []byte `cbor:"2,keyasint,omitempty"`
	// Optional
	PinRetries uint `cbor:"3,keyasint,omitempty"`
	// Optional
	PowerCycleState bool `cbor:"4,keyasint,omitempty"`
	// Optional
	UvRetries uint `cbor:"5,keyasint,omitempty"`
}

type PinUvAuthProtocolKey struct {
	*cose.Key
}

func (k *PinUvAuthProtocolKey) UnmarshalCBOR(data []byte) error {
	// Ignore error because their alg is -25(invalid)
	k.Key = &cose.Key{}
	k.Key.UnmarshalCBOR(data)
	return nil
}

const AuthenticatorCredentialManagementCommandId uint8 = 0x0A

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
type AuthenticatorCredentialManagementRequest struct {
	SubCommand        AuthenticatorCredentialManagementRequestSubCommand        `cbor:"1,keyasint"`
	SubCommandParams  *AuthenticatorCredentialManagementRequestSubCommandParams `cbor:"2,keyasint,omitempty"`
	PinUvAuthProtocol uint                                                      `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte                                                    `cbor:"4,keyasint,omitempty"`
}

type AuthenticatorCredentialManagementRequestSubCommand uint

const (
	AuthenticatorCredentialManagementRequestSubCommandGetCredsMetadata                     AuthenticatorCredentialManagementRequestSubCommand = 0x01
	AuthenticatorCredentialManagementRequestSubCommandEnumlateRPsBegin                     AuthenticatorCredentialManagementRequestSubCommand = 0x02
	AuthenticatorCredentialManagementRequestSubCommandEnumlateRPsGetNextRP                 AuthenticatorCredentialManagementRequestSubCommand = 0x03
	AuthenticatorCredentialManagementRequestSubCommandEnumlateCredentialsBegin             AuthenticatorCredentialManagementRequestSubCommand = 0x04
	AuthenticatorCredentialManagementRequestSubCommandEnumlateCredentialsGetNextCredential AuthenticatorCredentialManagementRequestSubCommand = 0x05
	AuthenticatorCredentialManagementRequestSubCommandDeleteCredential                     AuthenticatorCredentialManagementRequestSubCommand = 0x06
	AuthenticatorCredentialManagementRequestSubCommandUpdateUserInformation                AuthenticatorCredentialManagementRequestSubCommand = 0x07
)

type AuthenticatorCredentialManagementRequestSubCommandParams struct {
	RPIDHash     []byte                              `cbor:"1,keyasint,omitempty"`
	CredentialID *fido.PublicKeyCredentialDescriptor `cbor:"2,keyasint,omitempty"`
	User         *fido.PublicKeyCredentialUserEntity `cbor:"3,keyasint,omitempty"`
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
type AuthenticatorCredentialManagementResponse struct {
	ExistingResidentCredentialsCount             uint                               `cbor:"1,keyasint,omitempty"`
	MaxPossibleRemainingResidentCredentialsCount uint                               `cbor:"2,keyasint,omitempty"`
	RP                                           fido.PublicKeyCredentialRpEntity   `cbor:"3,keyasint,omitempty"`
	RPIDHash                                     []byte                             `cbor:"4,keyasint,omitempty"`
	TotalRPs                                     uint                               `cbor:"5,keyasint,omitempty"`
	User                                         fido.PublicKeyCredentialUserEntity `cbor:"6,keyasint,omitempty"`
	CredentialID                                 fido.PublicKeyCredentialDescriptor `cbor:"7,keyasint,omitempty"`
	PublicKey                                    *cose.Key                          `cbor:"8,keyasint,omitempty"`
	TotalCredentials                             uint                               `cbor:"9,keyasint,omitempty"`
	CredProtect                                  uint                               `cbor:"10,keyasint,omitempty"`
	LargeBlobKey                                 []byte                             `cbor:"11,keyasint,omitempty"`
	ThirdPartyPayment                            bool                               `cbor:"12,keyasint,omitempty"`
}
