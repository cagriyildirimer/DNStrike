package dnsengine

import (
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

type IPManager struct {
	allocatedIPs []string
	iface        string
	enabled      bool
}

var ErrSourceIPPoolDisabled = errors.New("source IP pool allocation is disabled")

func NewIPManager(enabled bool) *IPManager {
	iface := "eth0"
	if enabled {
		out, err := exec.Command("ip", "route", "show", "default").Output()
		if err == nil {
			fields := strings.Fields(string(out))
			for index := 0; index+1 < len(fields); index++ {
				if fields[index] == "dev" {
					iface = fields[index+1]
					break
				}
			}
		}
	}
	return &IPManager{
		allocatedIPs: make([]string, 0),
		iface:        iface,
		enabled:      enabled,
	}
}

func (m *IPManager) Allocate(ip string) error {
	if !m.enabled {
		return ErrSourceIPPoolDisabled
	}
	cmd := exec.Command("ip", "addr", "add", ip+"/32", "dev", m.iface)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add IP %s to %s: %w", ip, m.iface, err)
	}
	m.allocatedIPs = append(m.allocatedIPs, ip)
	slog.Info("allocated IP alias", "ip", ip, "iface", m.iface)
	return nil
}

func (m *IPManager) ReleaseAll() {
	for _, ip := range m.allocatedIPs {
		cmd := exec.Command("ip", "addr", "del", ip+"/32", "dev", m.iface)
		if err := cmd.Run(); err != nil {
			slog.Error("failed to release IP", "ip", ip, "error", err)
		} else {
			slog.Info("released IP alias", "ip", ip, "iface", m.iface)
		}
	}
	m.allocatedIPs = nil
}
