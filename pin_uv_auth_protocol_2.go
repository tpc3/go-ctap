package ctap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log"

	"github.com/veraison/go-cose"
	"golang.org/x/crypto/hkdf"
)

type PinUVAuthProtocol2 struct {
	KeyAgreementKey *ecdsa.PrivateKey
	PinUvAuthToken  []byte
}

func (p *PinUVAuthProtocol2) Version() uint {
	return 2
}

func (p *PinUVAuthProtocol2) Initialize() {
	var err error
	p.KeyAgreementKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Panic("Failed to generate KeyAgreementKey: ", err)
	}
}

func (p *PinUVAuthProtocol2) getPublicKey() *PinUvAuthProtocolKey {
	key, err := cose.NewKeyFromPublic(p.KeyAgreementKey.Public())
	if err != nil {
		log.Panic("Failed to getPublicKey: ", err)
	}
	key.Algorithm = cose.Algorithm(-25)
	return &PinUvAuthProtocolKey{
		Key: key,
	}
}

func (p *PinUVAuthProtocol2) Encapsulate(peerCoseKey *PinUvAuthProtocolKey) (*PinUvAuthProtocolKey, []byte, error) {
	sharedSecret, err := p.ecdh(peerCoseKey)
	return p.getPublicKey(), sharedSecret, err
}

func (p *PinUVAuthProtocol2) Encrypt(key []byte, demPlainText []byte) []byte {
	rawCipher, err := aes.NewCipher(key[32:])
	if err != nil {
		log.Panic("Failed to initialize cipher: ", err)
	}
	res := make([]byte, len(demPlainText)+16)
	n, err := rand.Read(res[:16])
	if err != nil {
		log.Panic("Failed to generate IV: ", err)
	}
	if n != 16 {
		log.Panic("Failed to generate IV: invalid length")
	}
	c := cipher.NewCBCEncrypter(rawCipher, res[:16])
	c.CryptBlocks(res[16:], demPlainText)
	return res
}

func (p *PinUVAuthProtocol2) Decrypt(key []byte, demCipherText []byte) ([]byte, error) {
	rawCipher, err := aes.NewCipher(key[32:])
	if err != nil {
		log.Panic("Failed to initialize cipher: ", err)
	}
	if len(demCipherText) < 16 {
		return nil, errors.New("invalid message length")
	}
	iv := demCipherText[:16]
	ct := demCipherText[16:]
	c := cipher.NewCBCDecrypter(rawCipher, iv)
	res := make([]byte, len(ct))
	c.CryptBlocks(res, ct)
	return res, nil
}

func (p *PinUVAuthProtocol2) Authenticate(key []byte, message []byte) []byte {
	m := hmac.New(sha256.New, key[:32])
	m.Write(message)
	return m.Sum(nil)
}

func (p *PinUVAuthProtocol2) ecdh(peerCoseKey *PinUvAuthProtocolKey) ([]byte, error) {
	peerCoseKey.Algorithm = cose.AlgorithmES256
	peerKeyParsed, err := peerCoseKey.PublicKey()
	if err != nil {
		return nil, err
	}
	peerKey, ok := peerKeyParsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrProtocolUnsupported
	}
	ecdhSelf, err := p.KeyAgreementKey.ECDH()
	if err != nil {
		return nil, err
	}
	ecdhPeer, err := peerKey.ECDH()
	if err != nil {
		return nil, err
	}
	z, err := ecdhSelf.ECDH(ecdhPeer)
	if err != nil {
		return nil, err
	}
	return p.kdf(z), nil
}

func (p *PinUVAuthProtocol2) kdf(z []byte) []byte {
	res := make([]byte, 64)
	reader := hkdf.New(sha256.New, z, make([]byte, 32), []byte("CTAP2 HMAC key"))
	reader.Read(res[:32])
	reader = hkdf.New(sha256.New, z, make([]byte, 32), []byte("CTAP2 AES key"))
	reader.Read(res[32:])
	return res
}
