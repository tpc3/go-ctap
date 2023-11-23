package ctap_pcsc

import (
	"errors"
	"fmt"

	"github.com/ebfe/scard"
	"github.com/tpc3/go-ctap"
)

type DevicePCSC struct {
	card *scard.Card
}

var ErrAPDUStatus = errors.New("status word in APDU is not OK")

type APDUNotSuccessError struct {
	SW1 uint8
	SW2 uint8
}

func (e *APDUNotSuccessError) Error() string {
	return fmt.Sprintf("%s: %02x%02x", ErrAPDUStatus.Error(), e.SW1, e.SW2)
}

func (e *APDUNotSuccessError) Unwrap() error {
	return ErrAPDUStatus
}

var header = []byte{0x80, 0x10, 0x00, 0x00}

func (d *DevicePCSC) SendCommand(command byte, data []byte) ([]byte, error) {
	lc := len(data) + 1
	req := make([]byte, len(header), len(header)+3+lc)
	copy(req, header)
	req = append(req, 0x00, byte((lc>>8)&0xFF), byte(lc&0xFF), command)
	req = append(req, data...)
	resp, err := d.card.Transmit(req)
	if err != nil {
		return resp, err
	}
	if !(resp[len(resp)-2] == 0x90 && resp[len(resp)-1] == 0x00) {
		return resp, &APDUNotSuccessError{
			SW1: resp[len(resp)-2],
			SW2: resp[len(resp)-1],
		}
	}
	if resp[0] != 0x00 {
		return resp, ctap.CTAPStatusError(resp[0])
	}
	return resp[1 : len(resp)-2], nil
}

func NewDevice(card *scard.Card) (*ctap.Device, error) {
	d := ctap.Device{
		DeviceImpl: &DevicePCSC{
			card: card,
		},
	}
	return &d, d.Init()
}

func (d *DevicePCSC) Init() error {
	return d.setApplet()
}

func (d *DevicePCSC) setApplet() error {
	resp, err := d.card.Transmit([]byte{0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01})
	if err != nil {
		return err
	}
	if resp[len(resp)-2] == 0x90 && resp[len(resp)-1] == 0x00 {
		return nil
	} else {
		return &APDUNotSuccessError{
			SW1: resp[len(resp)-2],
			SW2: resp[len(resp)-1],
		}
	}
}
