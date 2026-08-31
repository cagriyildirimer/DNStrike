package models

import "time"

type Target struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	IPAddress   string    `json:"ip_address"`
	Port        int       `json:"port"`
	Description string    `json:"description"`
	Environment string    `json:"environment"`
	UDPEnabled  bool      `json:"udp_enabled"`
	TCPEnabled  bool      `json:"tcp_enabled"`
	Tags        []string  `json:"tags"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateTargetInput struct {
	Name        string   `json:"name"`
	IPAddress   string   `json:"ip_address"`
	Port        int      `json:"port"`
	Description string   `json:"description"`
	Environment string   `json:"environment"`
	UDPEnabled  *bool    `json:"udp_enabled"`
	TCPEnabled  *bool    `json:"tcp_enabled"`
	Tags        []string `json:"tags"`
}
