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
)

type PinUVAuthProtocol1 struct {
	KeyAgreementKey *ecdsa.PrivateKey
	PinUvAuthToken  []byte
}

func (p *PinUVAuthProtocol1) Version() uint {
	return 1
}

func (p *PinUVAuthProtocol1) Initialize() {
	var err error
	p.KeyAgreementKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Panic("Failed to generate KeyAgreementKey: ", err)
	}
}

func (p *PinUVAuthProtocol1) getPublicKey() *PinUvAuthProtocolKey {
	key, err := cose.NewKeyFromPublic(p.KeyAgreementKey.Public())
	if err != nil {
		log.Panic("Failed to getPublicKey: ", err)
	}
	key.Algorithm = cose.Algorithm(-25)
	return &PinUvAuthProtocolKey{
		Key: key,
	}
}

func (p *PinUVAuthProtocol1) Encapsulate(peerCoseKey *PinUvAuthProtocolKey) (*PinUvAuthProtocolKey, []byte, error) {
	sharedSecret, err := p.ecdh(peerCoseKey)
	return p.getPublicKey(), sharedSecret, err
}

func (p *PinUVAuthProtocol1) Encrypt(key []byte, demPlainText []byte) []byte {
	rawCipher, err := aes.NewCipher(key)
	if err != nil {
		log.Panic("Failed to initialize cipher: ", err)
	}
	c := cipher.NewCBCEncrypter(rawCipher, make([]byte, rawCipher.BlockSize()))
	res := make([]byte, len(demPlainText))
	c.CryptBlocks(res, demPlainText)
	return res
}

func (p *PinUVAuthProtocol1) Decrypt(key []byte, demCipherText []byte) ([]byte, error) {
	rawCipher, err := aes.NewCipher(key)
	if err != nil {
		log.Panic("Failed to initialize cipher: ", err)
	}
	c := cipher.NewCBCDecrypter(rawCipher, make([]byte, rawCipher.BlockSize()))
	if len(demCipherText)%c.BlockSize() != 0 {
		return nil, errors.New("invalid message length")
	}
	res := make([]byte, len(demCipherText))
	c.CryptBlocks(res, demCipherText)
	return res, nil
}

func (p *PinUVAuthProtocol1) Authenticate(key []byte, message []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(message)
	return m.Sum(nil)[:16]
}

func (p *PinUVAuthProtocol1) ecdh(peerCoseKey *PinUvAuthProtocolKey) ([]byte, error) {
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

func (p *PinUVAuthProtocol1) kdf(z []byte) []byte {
	sum := sha256.Sum256(z)
	return sum[:]
}
