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

var queryTypes = map[string]uint16{
	"A": dns.TypeA, "AAAA": dns.TypeAAAA, "MX": dns.TypeMX, "TXT": dns.TypeTXT, "NS": dns.TypeNS,
	"PTR": dns.TypePTR, "SRV": dns.TypeSRV, "CNAME": dns.TypeCNAME, "DNSKEY": dns.TypeDNSKEY, "DS": dns.TypeDS,
}

type QueryEngine struct{ Timeout time.Duration }

func NewQueryEngine(timeout time.Duration) *QueryEngine { return &QueryEngine{Timeout: timeout} }

func (e *QueryEngine) Execute(ctx context.Context, target models.Target, query models.DNSQuery) (models.QueryResult, error) {
	result := models.QueryResult{Domain: query.Domain, QueryType: strings.ToUpper(query.QueryType), Protocol: strings.ToLower(query.Protocol), StartedAt: time.Now().UTC()}
	if err := validateQuery(target, &query); err != nil {
		return failResult(result, models.QueryValidation, err)
	}
	result.Domain = query.Domain
	result.QueryType = query.QueryType
	result.Protocol = query.Protocol
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(query.Domain), queryTypes[query.QueryType])
	message.RecursionDesired = true
	if query.EDNSPayload > 0 || query.DNSSECOK {
		payload := query.EDNSPayload
		if payload == 0 {
			payload = 1232
		}
		message.SetEdns0(payload, query.DNSSECOK)
	}
	client := &dns.Client{Net: query.Protocol, Timeout: e.Timeout}
	address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))
	response, rtt, err := client.ExchangeContext(ctx, message, address)
	result.Latency = rtt
	result.LatencyMS = ms(rtt)
	if err != nil {
		class := classifyQueryError(ctx, err)
		return failResult(result, class, errors.New(queryErrorMessage(class)))
	}
	if response == nil {
		return failResult(result, models.QueryMalformedResponse, errors.New("DNS sunucusu boş yanıt döndürdü"))
	}
	packed, err := response.Pack()
	if err != nil {
		return failResult(result, models.QueryMalformedResponse, errors.New("DNS yanıtı işlenemedi"))
	}
	result.ResponseSize = len(packed)
	result.Truncated = response.Truncated
	result.RCode = response.Rcode
	result.RCodeName = dns.RcodeToString[response.Rcode]
	if result.RCodeName == "" {
		result.RCodeName = fmt.Sprintf("RCODE_%d", response.Rcode)
	}
	return result, nil
}

func validateQuery(target models.Target, query *models.DNSQuery) error {
	if err := security.ValidatePrivateIP(target.IPAddress); err != nil {
		return err
	}
	if target.Port < 1 || target.Port > 65535 {
		return errors.New("geçersiz DNS portu")
	}
	query.Protocol = strings.ToLower(strings.TrimSpace(query.Protocol))
	if query.Protocol != "udp" && query.Protocol != "tcp" {
		return errors.New("protokol udp veya tcp olmalıdır")
	}
	if query.Protocol == "udp" && !target.UDPEnabled {
		return errors.New("target için UDP etkin değil")
	}
	if query.Protocol == "tcp" && !target.TCPEnabled {
		return errors.New("target için TCP etkin değil")
	}
	query.Domain = strings.TrimSpace(query.Domain)
	if query.Domain == "" {
		return errors.New("domain zorunludur")
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(query.Domain)); !ok {
		return errors.New("geçersiz DNS domain adı")
	}
	query.QueryType = strings.ToUpper(strings.TrimSpace(query.QueryType))
	if _, ok := queryTypes[query.QueryType]; !ok {
		return errors.New("desteklenmeyen DNS query type")
	}
	if query.EDNSPayload > 0 && query.EDNSPayload < 512 {
		return errors.New("EDNS payload en az 512 olmalıdır")
	}
	return nil
}
func failResult(result models.QueryResult, class models.QueryErrorClass, err error) (models.QueryResult, error) {
	result.ErrorClass = class
	result.ErrorMessage = err.Error()
	return result, err
}
func classifyQueryError(ctx context.Context, err error) models.QueryErrorClass {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return models.QueryCancelled
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return models.QueryTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return models.QueryTimeout
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "refused") {
		return models.QueryConnectionRefused
	}
	if strings.Contains(text, "unreachable") || strings.Contains(text, "no route") {
		return models.QueryNetworkUnreachable
	}
	return models.QueryMalformedResponse
}
func queryErrorMessage(class models.QueryErrorClass) string {
	switch class {
	case models.QueryCancelled:
		return "DNS sorgusu iptal edildi"
	case models.QueryTimeout:
		return "DNS sorgusu zaman aşımına uğradı"
	case models.QueryConnectionRefused:
		return "DNS bağlantısı reddedildi"
	case models.QueryNetworkUnreachable:
		return "DNS ağına erişilemiyor"
	default:
		return "DNS sorgusu tamamlanamadı"
	}
}
