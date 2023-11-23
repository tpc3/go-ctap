# Go Library for FIDO CTAP2
[![Go Reference](https://pkg.go.dev/badge/github.com/tpc3/go-ctap.svg)](https://pkg.go.dev/github.com/tpc3/go-ctap)
[![Go Report Card](https://goreportcard.com/badge/github.com/tpc3/go-ctap)](https://goreportcard.com/report/github.com/tpc3/go-ctap) 


## Introduction 
This library implements [FIDO Client to Authenticator Protocol(CTAP) 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html).

## Installation

```
go get github.com/tpc3/go-ctap
```

## Features
- Command request and response struct
- Command function
- PinUvAuth utility
- wrap PC/SC card

CTAP1 isn't implemented

## Usage
### Get device
- NFC: call `ctap_pcsc.NewDevice(card *scard.Card)`
- USB: WIP

### Get PinUvAuthToken
call `(ctap.Device).GetPinUvAuthToken(permission, rpId, pin)`

### Call CTAP commands
call `(ctap.Device).<command_name>`

Read example directory to get more usage.
