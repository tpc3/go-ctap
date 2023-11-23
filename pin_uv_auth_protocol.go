package ctap

type PinUVAuthProtocol interface {
	Version() uint
	Initialize()
	Encapsulate(*PinUvAuthProtocolKey) (*PinUvAuthProtocolKey, []byte, error)
	Encrypt([]byte, []byte) []byte
	Decrypt([]byte, []byte) ([]byte, error)
	Authenticate([]byte, []byte) []byte
}
