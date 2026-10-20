package models

import "time"

type QueryErrorClass string

const (
	QueryOK                 QueryErrorClass = ""
	QueryTimeout            QueryErrorClass = "Timeout"
	QueryConnectionRefused  QueryErrorClass = "ConnectionRefused"
	QueryNetworkUnreachable QueryErrorClass = "NetworkUnreachable"
	QueryMalformedResponse  QueryErrorClass = "MalformedResponse"
	QueryDNSRCodeError      QueryErrorClass = "DNSRCodeError"
	QueryCancelled          QueryErrorClass = "Cancelled"
	QueryValidation         QueryErrorClass = "ValidationError"
)

type DNSQuery struct {
	Domain       string `json:"domain"`
	QueryType    string `json:"query_type"`
	QueryClass   string `json:"query_class,omitempty"`
	Protocol     string `json:"protocol"`
	SourceIP     string `json:"source_ip,omitempty"`
	EDNSPayload  uint16 `json:"edns_payload,omitempty"`
	DNSSECOK     bool   `json:"dnssec_ok,omitempty"`
	ClientSubnet string `json:"client_subnet,omitempty"`
}

type QueryResult struct {
	Domain             string          `json:"domain"`
	QueryType          string          `json:"query_type"`
	Protocol           string          `json:"protocol"`
	StartedAt          time.Time       `json:"started_at"`
	Latency            time.Duration   `json:"-"`
	LatencyMS          float64         `json:"latency_ms"`
	RCode              int             `json:"rcode"`
	RCodeName          string          `json:"rcode_name"`
	ResponseSize       int             `json:"response_size"`
	AnswerCount        int             `json:"answer_count"`
	AnswerTypes        []string        `json:"answer_types,omitempty"`
	Truncated          bool            `json:"truncated"`
	RecursionAvailable bool            `json:"recursion_available"`
	ECSResponse        bool            `json:"ecs_response"`
	ErrorClass         QueryErrorClass `json:"error_class,omitempty"`
	ErrorMessage       string          `json:"error_message,omitempty"`
}
