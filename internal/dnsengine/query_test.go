package dnsengine

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/dnstrike/dnstrike/pkg/models"
	"github.com/miekg/dns"
)

func TestQueryEngineUDP(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packetConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(r)
		response.RecursionAvailable = true
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.168.1.10")}}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	port := packetConn.LocalAddr().(*net.UDPAddr).Port
	target := models.Target{IPAddress: "127.0.0.1", Port: port, UDPEnabled: true}
	result, err := NewQueryEngine(time.Second).Execute(context.Background(), target, models.DNSQuery{Domain: "example.test", QueryType: "a", Protocol: "UDP"})
	if err != nil {
		t.Fatal(err)
	}
	if result.RCode != dns.RcodeSuccess || result.ResponseSize == 0 || result.Protocol != "udp" || result.QueryType != "A" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestQueryEngineRejectsPublicTarget(t *testing.T) {
	result, err := NewQueryEngine(time.Second).Execute(context.Background(), models.Target{IPAddress: "8.8.8.8", Port: 53, UDPEnabled: true}, models.DNSQuery{Domain: "example.com", QueryType: "A", Protocol: "udp"})
	if err == nil || result.ErrorClass != models.QueryValidation {
		t.Fatalf("expected safe target rejection, result=%#v err=%v", result, err)
	}
}

func TestQueryEngineRejectsDisabledProtocol(t *testing.T) {
	result, err := NewQueryEngine(time.Second).Execute(context.Background(), models.Target{IPAddress: "127.0.0.1", Port: 53, TCPEnabled: true}, models.DNSQuery{Domain: "example.com", QueryType: "A", Protocol: "udp"})
	if err == nil || result.ErrorClass != models.QueryValidation {
		t.Fatalf("expected disabled protocol rejection, result=%#v err=%v", result, err)
	}
}
