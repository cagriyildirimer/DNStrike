package dnsengine

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

type IPManager struct {
	allocatedIPs []string
	iface        string
}

func NewIPManager() *IPManager {
	out, err := exec.Command("sh", "-c", "ip route show default | awk '{print $5}'").Output()
	iface := "eth0"
	if err == nil {
		str := strings.TrimSpace(string(out))
		if str != "" {
			iface = strings.Split(str, "\n")[0]
		}
	}
	return &IPManager{
		allocatedIPs: make([]string, 0),
		iface:        iface,
	}
}

func (m *IPManager) Allocate(ip string) error {
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
