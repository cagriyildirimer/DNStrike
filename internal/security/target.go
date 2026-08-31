package security

import (
	"errors"
	"net"
)

var ErrPublicTarget = errors.New("yalnızca private veya local IP adreslerine izin verilir")

func ValidatePrivateIP(value string) error {
	ip := net.ParseIP(value)
	if ip == nil {
		return errors.New("geçerli bir IP adresi girin")
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil
	}
	return ErrPublicTarget
}
