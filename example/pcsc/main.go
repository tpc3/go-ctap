package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"syscall"

	"github.com/ebfe/scard"
	"github.com/tpc3/go-ctap"
	"github.com/tpc3/go-ctap/impl/ctap_pcsc"
	"github.com/tpc3/go-fido"
	"github.com/veraison/go-cose"
	"golang.org/x/term"
)

var rpId = "example_rp"
var rpName = "Example RP"

var userId = "example_user"
var userName = "Example User"

func main() {
	ctx, err := scard.EstablishContext()
	if err != nil {
		log.Fatal("Failed to establish PC/SC context: ", err)
	}
	readers, err := ctx.ListReaders()
	if err != nil {
		log.Fatal("Failed to list PC/SC readers: ", err)
	}
	if len(readers) != 1 {
		log.Fatal("Found no or more than one PC/SC readers")
	}

	fmt.Print("Enter PIN: ")
	pin, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Panic("Failed to read PIN: ", err)
	}

	card, err := ctx.Connect(readers[0], scard.ShareShared, scard.ProtocolT1)
	if err != nil {
		log.Fatal("Failed to connect card: ", err)
	}

	dev, err := ctap_pcsc.NewDevice(card)
	if err != nil {
		log.Panic("Failed to make CTAP device: ", err)
	}

	info, err := dev.GetInfo()
	if err != nil {
		log.Panic("Failed to get info: ", err)
	}

	log.Print("Get info: ", info)

	resp, err := dev.ClientPIN(ctap.AuthenticatorClientPINRequest{
		SubCommand: ctap.AuthenticatorClientPINRequestSubCommandGetPINRetries,
	})
	if err != nil {
		log.Panic("Failed to get pin retries: ", err)
	}

	log.Print("PIN retries: ", resp.PinRetries)

	if string(pin) != "" && resp.PinRetries < 5 {
		log.Panic("Too danger to test PIN: ", err)
	}

	token, err := dev.GetPinUvAuthToken((ctap.PinUvAuthTokenPermissionMakeCredential | ctap.PinUvAuthTokenPermissionGetAssertion), "test_rp", string(pin))
	if err != nil {
		log.Panic("Failed to get token: ", err)
	}

	hash := make([]byte, 32)
	_, err = rand.Read(hash)
	if err != nil {
		log.Panic("Failed to generate hash: ", err)
	}

	makeCredRes, err := dev.MakeCredential(ctap.AuthenticatorMakeCredentialRequest{
		ClientDataHash: hash[:],
		RP: fido.PublicKeyCredentialRpEntity{
			Name: rpName,
			ID:   rpId,
		},
		User: fido.PublicKeyCredentialUserEntity{
			Name:        userId,
			ID:          []byte(userId),
			DisplayName: userName,
		},
		PubKeyCredParams: []fido.PublicKeyCredentialParameters{
			{
				Type: "public-key",
				Alg:  cose.AlgorithmEdDSA,
			},
		},
		Options: ctap.AuthenticatorMakeCredentialRequestOptions{
			// RK: true,
		},
		PinUvAuthParam:    dev.PinUVAuthProtocol.Authenticate(token, hash[:]),
		PinUvAuthProtocol: dev.PinUVAuthProtocol.Version(),
	})
	if err != nil {
		log.Panic("Failed to make cred: ", err)
	}

	// stmt := ctap.PackedAttestationStatement{}

	// cbor.Unmarshal(makeCredRes.AttStmt, &stmt)

	// certs := make([]*x509.Certificate, len(stmt.X5c))

	// for i, v := range stmt.X5c {
	// 	certs[i], err = x509.ParseCertificate(v)
	// 	if err != nil {
	// 		log.Panic("Failed to parse certificate: ", err)
	// 	}
	// 	log.Print("cert: ", certs[i])
	// }

	authData := fido.AuthenticatorData{}
	err = authData.UnmarshalBinary(makeCredRes.AuthData)
	if err != nil {
		log.Panic("Failed to unmarshal AuthData: ", err)
	}

	pubkeyRaw, err := authData.AttestedCredentialData.CredentialPublicKey.PublicKey()
	if err != nil {
		log.Panic("Failed to parse public key: ", err)
	}
	pubkey, ok := pubkeyRaw.(ed25519.PublicKey)
	if !ok {
		log.Panic("Failed to public key is not ed25519")
	}

	log.Print("Make credential: ", makeCredRes)

	getAssertRes, err := dev.GetAssertion(ctap.AuthenticatorGetAssertionRequest{
		RPID:           rpId,
		ClientDataHash: hash[:],
		AllowList: []fido.PublicKeyCredentialDescriptor{
			{
				Type: "public-key",
				ID:   authData.AttestedCredentialData.CredentialId,
			},
		},
	})
	if err != nil {
		log.Panic("Failed to get assert: ", err)
	}
	log.Print("Get assert: ", getAssertRes)

	sigRes := ed25519.Verify(pubkey, append(getAssertRes.AuthData, hash[:]...), getAssertRes.Signature)
	if !sigRes {
		log.Panic("Failed to check signature")
	}

	log.Print("end")
}
