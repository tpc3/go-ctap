package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ebfe/scard"
	"github.com/tpc3/go-ctap"
	"github.com/tpc3/go-ctap/impl/ctap_pcsc"
	"github.com/tpc3/go-fido"
	"github.com/veraison/go-cose"
)

func main() {

	commonFlag := flag.NewFlagSet("common", flag.ExitOnError)

	method := commonFlag.String("method", "pcsc", "Specify how to connect authenticator.\n Available options: pcsc(default)")
	rpId := commonFlag.String("rpid", "example_rp", "RP ID")
	rpName := commonFlag.String("rpname", "Example RP", "RP Name")
	userId := commonFlag.String("userid", "example_user", "User ID")
	userName := commonFlag.String("username", "Example User", "User Name")

	database := commonFlag.String("database", "./data.json", "Specify file(json) to save created credentials")

	commonFlag.Parse(os.Args[1:])

	args := commonFlag.Args()
	subCmd := ""
	if len(args) >= 1 {
		subCmd = args[0]
	}

	dev, err := GetDevice(*method)
	if err != nil {
		log.Panic("Failed to connect device: ", err)
	}

	data := LoadData(*database)

	switch subCmd {
	case "register":
		{
			registerFlag := flag.NewFlagSet("register", flag.ExitOnError)
			rk := registerFlag.Bool("rk", false, "Whether credential to be discoverable(resident) or not")
			uv := registerFlag.Bool("uv", false, "Use built-in User Verification")
			registerFlag.Parse(args[1:])

			hash := make([]byte, 32)
			_, err = rand.Read(hash)
			if err != nil {
				log.Panic("Failed to generate hash: ", err)
			}

			req := ctap.AuthenticatorMakeCredentialRequest{
				ClientDataHash: hash,
				RP: fido.PublicKeyCredentialRpEntity{
					Name: *rpName,
					ID:   *rpId,
				},
				User: fido.PublicKeyCredentialUserEntity{
					Name:        *userId,
					ID:          []byte(*userId),
					DisplayName: *userName,
				},
				PubKeyCredParams: []fido.PublicKeyCredentialParameters{
					{
						Type: "public-key",
						Alg:  cose.AlgorithmEdDSA,
					},
				},
				Options: ctap.AuthenticatorMakeCredentialRequestOptions{
					RK: *rk,
				},
			}

			if *rk || *uv || !dev.Info.IsOptionTrue("makeCredUvNotRqd") {
				pin := make([]byte, 0)
				if !*uv {
					fmt.Print("Enter PIN: ")
					fmt.Scan(&pin)
				}

				token, err := dev.GetPinUvAuthToken(ctap.PinUvAuthTokenPermissionMakeCredential, *rpId, string(pin))
				if err != nil {
					log.Panic("Failed to get auth token: ", err)
				}

				req.PinUvAuthParam = dev.PinUVAuthProtocol.Authenticate(token, hash)
				req.PinUvAuthProtocol = dev.PinUVAuthProtocol.Version()
			}

			resp, err := dev.MakeCredential(req)
			if err != nil {
				log.Panic("Failed to make credential: ", err)
			}

			authData := fido.AuthenticatorData{}
			err = authData.UnmarshalBinary(resp.AuthData)
			if err != nil {
				log.Panic("Failed to unmarshal AuthData: ", err)
			}

			if authData.AttestedCredentialData.CredentialPublicKey.Algorithm != cose.AlgorithmEdDSA {
				log.Panic("Failed to make credential: ", err)
			}

			keyRaw, err := authData.AttestedCredentialData.CredentialPublicKey.PublicKey()
			if err != nil {
				log.Panic("Failed to parse pubkey: ", err)
			}
			key, ok := keyRaw.(ed25519.PublicKey)
			if !ok {
				log.Panic("Invalid pubkey type: ", err)
			}

			data = append(data, PersistData{
				User:         *userId,
				CredentialId: base64.StdEncoding.EncodeToString(authData.AttestedCredentialData.CredentialId),
				Algo:         int(authData.AttestedCredentialData.CredentialPublicKey.Algorithm),
				PublicKey:    base64.StdEncoding.EncodeToString(key),
			})
			SaveData(*database, data)
		}
	case "assert":
		{
			assertFlag := flag.NewFlagSet("assert", flag.ExitOnError)
			up := assertFlag.Bool("up", false, "Require User Presence")
			uv := assertFlag.Bool("uv", false, "Use built-in User Verification")
			pin := assertFlag.Bool("pin", false, "Use clientPin")
			rk := assertFlag.Bool("rk", false, "Don't send credential ID(ignore userId)")
			assertFlag.Parse(args[1:])

			hash := make([]byte, 32)
			_, err = rand.Read(hash)
			if err != nil {
				log.Panic("Failed to generate hash: ", err)
			}

			req := ctap.AuthenticatorGetAssertionRequest{
				RPID:           *rpId,
				ClientDataHash: hash,
				Options: ctap.AuthenticatorGetAssertionRequestOptions{
					UP: *up,
				},
			}

			if !*rk {
				req.AllowList = []fido.PublicKeyCredentialDescriptor{}
				for _, v := range data {
					if v.User != *userId {
						continue
					}
					id, err := base64.StdEncoding.DecodeString(v.CredentialId)
					if err != nil {
						log.Panic("Failed to decode credential ID in data: ", err)
					}
					req.AllowList = append(req.AllowList, fido.PublicKeyCredentialDescriptor{
						Type: "public-key",
						ID:   id,
					})
				}
			}

			if *uv || *pin {
				pinData := make([]byte, 0)
				if *pin {
					fmt.Print("Enter PIN: ")
					fmt.Scan(&pinData)
				}

				token, err := dev.GetPinUvAuthToken(ctap.PinUvAuthTokenPermissionMakeCredential, *rpId, string(pinData))
				if err != nil {
					log.Panic("Failed to get auth token: ", err)
				}

				req.PinUvAuthParam = dev.PinUVAuthProtocol.Authenticate(token, hash)
				req.PinUvAuthProtocol = dev.PinUVAuthProtocol.Version()
			}

			resp, err := dev.GetAssertion(req)
			if err != nil {
				log.Panic("Failed to get assertion: ", err)
			}

			var record PersistData
			base64id := base64.StdEncoding.EncodeToString(resp.Credential.ID)
			for _, v := range data {
				if base64id == v.CredentialId {
					record = v
					break
				}
			}

			result := false

			switch record.Algo {
			case 0:
				log.Print("Data not found")
			case int(cose.AlgorithmEdDSA):
				rawKey, err := base64.StdEncoding.DecodeString(record.PublicKey)
				if err != nil {
					log.Panic("Failed to decode key in data: ", err)
				}
				key := ed25519.PublicKey(rawKey)
				result = ed25519.Verify(key, append(resp.AuthData, hash...), resp.Signature)
			default:
				log.Print("Key algorithm unsupported")
			}

			if result {
				log.Print("Successfully authenticated as ", record.User)
			} else {
				log.Print("Failed to authenticate")
			}
		}
	default:
		{
			log.Print("Select subcommand: register, assert")
		}
	}
}

func GetDevice(method string) (*ctap.Device, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, err
	}
	readers, err := ctx.ListReaders()
	if err != nil {
		return nil, err
	}
	if len(readers) != 1 {
		return nil, errors.New("found no or more than one PC/SC readers")
	}

	log.Print("Waiting for authenticator...")
	err = ctx.GetStatusChange([]scard.ReaderState{
		{
			Reader:       readers[0],
			CurrentState: scard.StateEmpty,
		},
	}, -1)
	if err != nil {
		log.Panic("failed to wait authenticator: ", err)
	}
	card, err := ctx.Connect(readers[0], scard.ShareShared, scard.ProtocolT1)
	if err != nil {
		return nil, err
	}

	return ctap_pcsc.NewDevice(card)
}

type PersistData struct {
	User         string
	CredentialId string
	Algo         int
	PublicKey    string
}

func LoadData(path string) (data []PersistData) {
	data = make([]PersistData, 0)
	file, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		log.Panic("Failed to open data file: ", err)
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	err = dec.Decode(&data)
	if err != nil {
		log.Panic("Failed to decode data file: ", err)
	}
	return
}

func SaveData(path string, data []PersistData) {
	file, err := os.OpenFile(path, os.O_WRONLY, os.ModePerm)
	if errors.Is(err, os.ErrNotExist) {
		file, err = os.Create(path)
	}
	if err != nil {
		log.Panic("Failed to open data file: ", err)
	}
	defer file.Close()
	dec := json.NewEncoder(file)
	err = dec.Encode(data)
	if err != nil {
		log.Panic("Failed to encode data: ", err)
	}
}
