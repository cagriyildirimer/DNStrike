package dnsengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/dnstrike/dnstrike/internal/security"
	"github.com/dnstrike/dnstrike/pkg/models"
)

type Discovery struct{ Timeout time.Duration }

func NewDiscovery(timeout time.Duration) *Discovery { return &Discovery{Timeout: timeout} }

func (d *Discovery) Run(ctx context.Context, target models.Target) (models.DiscoveryProfile, error) {
	if err := security.ValidatePrivateIP(target.IPAddress); err != nil {
		return models.DiscoveryProfile{}, err
	}
	address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))
	p := models.DiscoveryProfile{Target: address, CheckedAt: time.Now().UTC()}
	var latencyTotal float64
	var successes int
	var udpResponse *dns.Msg
	if target.UDPEnabled {
		resp, rtt, err := d.exchange(ctx, "udp", address, true)
		p.UDP = protocolResult(rtt, err)
		if err == nil {
			udpResponse = resp
			latencyTotal += ms(rtt)
			successes++
			applyResponse(&p, resp)
		}
	}
	if target.TCPEnabled {
		resp, rtt, err := d.exchange(ctx, "tcp", address, true)
		p.TCP = protocolResult(rtt, err)
		if err == nil {
			latencyTotal += ms(rtt)
			successes++
			if udpResponse == nil {
				applyResponse(&p, resp)
			}
		}
	}
	if udpResponse != nil && udpResponse.Truncated && target.TCPEnabled && p.TCP.Available {
		p.TCPFallback = true
	}
	if successes > 0 {
		p.AverageLatencyMS = latencyTotal / float64(successes)
	}
	return p, nil
}

func (d *Discovery) exchange(ctx context.Context, network, address string, edns bool) (*dns.Msg, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.RecursionDesired = true
	if edns {
		msg.SetEdns0(1232, true)
	}
	client := &dns.Client{Net: network, Timeout: d.Timeout}
	resp, rtt, err := client.ExchangeContext(ctx, msg, address)
	if err != nil {
		return nil, rtt, classify(err)
	}
	if resp == nil {
		return nil, rtt, errors.New("DNS sunucusu boş yanıt döndürdü")
	}
	return resp, rtt, nil
}
func protocolResult(rtt time.Duration, err error) models.ProtocolCheck {
	r := models.ProtocolCheck{Available: err == nil, LatencyMS: ms(rtt)}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}
func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
func applyResponse(p *models.DiscoveryProfile, r *dns.Msg) {
	p.RecursionEnabled = r.RecursionAvailable
	p.Authoritative = r.Authoritative
	p.Flags = models.DNSFlags{RA: r.RecursionAvailable, RD: r.RecursionDesired, AA: r.Authoritative, TC: r.Truncated}
	if packed, err := r.Pack(); err == nil {
		p.ResponseSize = len(packed)
	}
	for _, rr := range r.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			p.EDNSSupported = true
			if opt.Do() {
				p.DNSSECSupported = true
			}
		}
	}
	if r.AuthenticatedData {
		p.DNSSECSupported = true
	}
	for _, rr := range append(r.Answer, r.Ns...) {
		switch rr.(type) {
		case *dns.RRSIG, *dns.DNSKEY, *dns.DS:
			p.DNSSECSupported = true
		}
	}
}
func classify(err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.New("işlem iptal edildi")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("DNS sorgusu zaman aşımına uğradı")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("DNS sorgusu zaman aşımına uğradı")
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "refused") {
		return errors.New("bağlantı reddedildi")
	}
	if strings.Contains(s, "unreachable") {
		return errors.New("ağa erişilemiyor")
	}
	return errors.New("DNS sunucusuna ulaşılamadı")
}
