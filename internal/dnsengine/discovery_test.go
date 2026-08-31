package dnsengine

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/dnstrike/dnstrike/pkg/models"
	"github.com/miekg/dns"
)

func TestDiscoveryAgainstLocalDNS(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packetConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.168.1.20")}}
		m.SetEdns0(1232, true)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	port := packetConn.LocalAddr().(*net.UDPAddr).Port
	profile, err := NewDiscovery(time.Second).Run(context.Background(), models.Target{IPAddress: "127.0.0.1", Port: port, UDPEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !profile.UDP.Available {
		t.Fatalf("UDP unavailable: %s", profile.UDP.Error)
	}
	if !profile.RecursionEnabled || !profile.EDNSSupported || !profile.DNSSECSupported {
		t.Fatalf("unexpected profile: %#v", profile)
	}
	if profile.ResponseSize == 0 {
		t.Fatal("response size was not recorded")
	}
}
