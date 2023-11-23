package ctap

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var ErrProtocolUnsupported = errors.New("protocol unsupported")

var ErrCTAPStatus = errors.New("CTAP status code")

type CTAPStatusError uint8

func (e CTAPStatusError) Error() string {
	return fmt.Sprintf("%s: %s(%02X)", ErrCTAPStatus.Error(), e.GetName(), uint8(e))
}

func (e CTAPStatusError) Unwrap() error {
	return ErrCTAPStatus
}

func (e CTAPStatusError) GetName() string {
	switch e {
	case 0x00:
		return "CTAP2_OK"
	case 0x01:
		return "CTAP1_ERR_INVALID_COMMAND"
	case 0x02:
		return "CTAP1_ERR_INVALID_PARAMETER"
	case 0x03:
		return "CTAP1_ERR_INVALID_LENGTH"
	case 0x04:
		return "CTAP1_ERR_INVALID_SEQ"
	case 0x05:
		return "CTAP1_ERR_TIMEOUT"
	case 0x06:
		return "CTAP1_ERR_CHANNEL_BUSY"
	case 0x0A:
		return "CTAP1_ERR_LOCK_REQUIRED"
	case 0x0B:
		return "CTAP1_ERR_INVALID_CHANNEL"
	case 0x11:
		return "CTAP2_ERR_CBOR_UNEXPECTED_TYPE"
	case 0x12:
		return "CTAP2_ERR_INVALID_CBOR"
	case 0x14:
		return "CTAP2_ERR_MISSING_PARAMETER"
	case 0x15:
		return "CTAP2_ERR_LIMIT_EXCEEDED"
	case 0x17:
		return "CTAP2_ERR_FP_DATABASE_FULL"
	case 0x18:
		return "CTAP2_ERR_LARGE_BLOB_STORAGE_FULL"
	case 0x19:
		return "CTAP2_ERR_CREDENTIAL_EXCLUDED"
	case 0x21:
		return "CTAP2_ERR_PROCESSING"
	case 0x22:
		return "CTAP2_ERR_INVALID_CREDENTIAL"
	case 0x23:
		return "CTAP2_ERR_USER_ACTION_PENDING"
	case 0x24:
		return "CTAP2_ERR_OPERATION_PENDING"
	case 0x25:
		return "CTAP2_ERR_NO_OPERATIONS"
	case 0x26:
		return "CTAP2_ERR_UNSUPPORTED_ALGORITHM"
	case 0x27:
		return "CTAP2_ERR_OPERATION_DENIED"
	case 0x28:
		return "CTAP2_ERR_KEY_STORE_FULL"
	case 0x2B:
		return "CTAP2_ERR_UNSUPPORTED_OPTION"
	case 0x2C:
		return "CTAP2_ERR_INVALID_OPTION"
	case 0x2D:
		return "CTAP2_ERR_KEEPALIVE_CANCEL"
	case 0x2E:
		return "CTAP2_ERR_NO_CREDENTIALS"
	case 0x2F:
		return "CTAP2_ERR_USER_ACTION_TIMEOUT"
	case 0x30:
		return "CTAP2_ERR_NOT_ALLOWED"
	case 0x31:
		return "CTAP2_ERR_PIN_INVALID"
	case 0x32:
		return "CTAP2_ERR_PIN_BLOCKED"
	case 0x33:
		return "CTAP2_ERR_PIN_AUTH_INVALID"
	case 0x34:
		return "CTAP2_ERR_PIN_AUTH_BLOCKED"
	case 0x35:
		return "CTAP2_ERR_PIN_NOT_SET"
	case 0x36:
		return "CTAP2_ERR_PUAT_REQUIRED"
	case 0x37:
		return "CTAP2_ERR_PIN_POLICY_VIOLATION"
	case 0x39:
		return "CTAP2_ERR_REQUEST_TOO_LARGE"
	case 0x3A:
		return "CTAP2_ERR_ACTION_TIMEOUT"
	case 0x3B:
		return "CTAP2_ERR_UP_REQUIRED"
	case 0x3C:
		return "CTAP2_ERR_UV_BLOCKED"
	case 0x3D:
		return "CTAP2_ERR_INTEGRITY_FAILURE"
	case 0x3E:
		return "CTAP2_ERR_INVALID_SUBCOMMAND"
	case 0x3F:
		return "CTAP2_ERR_UV_INVALID"
	case 0x40:
		return "CTAP2_ERR_UNAUTHORIZED_PERMISSION"
	case 0x7F:
		return "CTAP1_ERR_OTHER"
	case 0xDF:
		return "CTAP2_ERR_SPEC_LAST"
	case 0xE0:
		return "CTAP2_ERR_EXTENSION_FIRST"
	case 0xEF:
		return "CTAP2_ERR_EXTENSION_LAST"
	case 0xF0:
		return "CTAP2_ERR_VENDOR_FIRST"
	case 0xFF:
		return "CTAP2_ERR_VENDOR_LAST"
	default:
		return "unknown"
	}
}

type Device struct {
	DeviceImpl
	Info              *AuthenticatorGetInfoResponse
	PinUVAuthProtocol PinUVAuthProtocol
}

type DeviceImpl interface {
	Init() error
	SendCommand(command byte, data []byte) ([]byte, error)
}

func (d *Device) Init() error {
	err := d.DeviceImpl.Init()
	if err != nil {
		return err
	}

	_, err = d.GetInfo()
	if err != nil {
		return err
	}

search_prot:
	for _, v := range d.Info.PinUvAuthProtocols {
		switch v {
		case 1:
			d.PinUVAuthProtocol = &PinUVAuthProtocol1{}
			break search_prot
		case 2:
			d.PinUVAuthProtocol = &PinUVAuthProtocol2{}
			break search_prot
		default:
			continue
		}
	}

	// // TODO: DEBUG
	// d.PinUVAuthProtocol = &PinUVAuthProtocol1{}

	if d.PinUVAuthProtocol == nil {
		return fmt.Errorf("%w: %s: %d", ErrProtocolUnsupported, "PinUvAuthProtocols", d.Info.PinUvAuthProtocols)
	}

	d.PinUVAuthProtocol.Initialize()

	return nil
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
func (d *Device) MakeCredential(req AuthenticatorMakeCredentialRequest) (resp *AuthenticatorMakeCredentialResponse, err error) {
	reqData, err := cbor.Marshal(req)
	if err != nil {
		return
	}
	rawResp, err := d.SendCommand(AuthenticatorMakeCredentialCommandId, reqData)
	if err != nil {
		return
	}
	err = cbor.Unmarshal(rawResp, &resp)
	return
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetAssertion
func (d *Device) GetAssertion(req AuthenticatorGetAssertionRequest) (resp *AuthenticatorGetAssertionResponse, err error) {
	reqData, err := cbor.Marshal(req)
	if err != nil {
		return
	}
	rawResp, err := d.SendCommand(AuthenticatorGetAssertionCommandId, reqData)
	if err != nil {
		return
	}
	err = cbor.Unmarshal(rawResp, &resp)
	return
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetNextAssertion
func (d *Device) GetNextAssertion(req AuthenticatorGetAssertionRequest) (resp *AuthenticatorGetAssertionResponse, err error) {
	reqData, err := cbor.Marshal(req)
	if err != nil {
		return
	}
	rawResp, err := d.SendCommand(AuthenticatorGetNextAssertionCommandId, reqData)
	if err != nil {
		return
	}
	err = cbor.Unmarshal(rawResp, &resp)
	return
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetInfo
func (d *Device) GetInfo() (resp *AuthenticatorGetInfoResponse, err error) {
	rawResp, err := d.SendCommand(AuthenticatorGetInfoCommandId, []byte{})
	if err != nil {
		return nil, err
	}
	err = cbor.Unmarshal(rawResp, &resp)
	if err == nil {
		d.Info = resp
	}
	return
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-cmd-dfn
func (d *Device) ClientPIN(req AuthenticatorClientPINRequest) (resp *AuthenticatorClientPINResponse, err error) {
	reqData, err := cbor.Marshal(req)
	if err != nil {
		return
	}
	rawResp, err := d.SendCommand(AuthenticatorClientPINCommandId, reqData)
	if err != nil {
		return
	}
	err = cbor.Unmarshal(rawResp, &resp)
	return
}

// rpId is optional(can be empty)
// to use UV, pin == ""
func (d *Device) GetPinUvAuthToken(permission PinUvAuthTokenPermission, rpID string, pin string) ([]byte, error) {
	resp, err := d.ClientPIN(AuthenticatorClientPINRequest{
		PinUvAuthProtocol: d.PinUVAuthProtocol.Version(),
		SubCommand:        AuthenticatorClientPINRequestSubCommandGetKeyAgreement,
	})
	if err != nil {
		return nil, err
	}

	platKey, secret, err := d.PinUVAuthProtocol.Encapsulate(resp.KeyAgreement)
	if err != nil {
		return nil, err
	}

	if pin == "" {
		resp, err = d.ClientPIN(AuthenticatorClientPINRequest{
			PinUvAuthProtocol: d.PinUVAuthProtocol.Version(),
			SubCommand:        AuthenticatorClientPINRequestSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
			KeyAgreement:      platKey,
			Permissions:       permission,
			RPID:              rpID,
		})
		if err == nil {
			return d.PinUVAuthProtocol.Decrypt(secret, resp.PinUvAuthToken)
		}
		return nil, err
	} else {
		pinHash := sha256.Sum256([]byte(pin))
		if d.Info.IsOptionTrue("clientPin") && d.Info.IsOptionTrue("pinUvAuthToken") {
			resp, err = d.ClientPIN(AuthenticatorClientPINRequest{
				PinUvAuthProtocol: d.PinUVAuthProtocol.Version(),
				SubCommand:        AuthenticatorClientPINRequestSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
				KeyAgreement:      platKey,
				PinHashEnc:        d.PinUVAuthProtocol.Encrypt(secret, pinHash[:16]),
				Permissions:       permission,
				RPID:              rpID,
			})
		} else {
			resp, err = d.ClientPIN(AuthenticatorClientPINRequest{
				PinUvAuthProtocol: d.PinUVAuthProtocol.Version(),
				SubCommand:        AuthenticatorClientPINRequestSubCommandGetPINToken,
				KeyAgreement:      platKey,
				PinHashEnc:        d.PinUVAuthProtocol.Encrypt(secret, pinHash[:16]),
			})
		}
		if err != nil {
			return nil, err
		}
		return d.PinUVAuthProtocol.Decrypt(secret, resp.PinUvAuthToken)
	}
}
