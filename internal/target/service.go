package target

import (
	"context"
	"errors"
	"strings"

	"github.com/dnstrike/dnstrike/internal/security"
	"github.com/dnstrike/dnstrike/pkg/models"
)

type Repository interface {
	CreateTarget(context.Context, *models.Target) error
	ListTargets(context.Context) ([]models.Target, error)
	GetTarget(context.Context, int64) (models.Target, error)
	DeleteTarget(context.Context, int64) error
}

type Service struct{ repo Repository }

func NewService(repo Repository) *Service { return &Service{repo: repo} }

func (s *Service) Create(ctx context.Context, in models.CreateTargetInput) (models.Target, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.IPAddress = strings.TrimSpace(in.IPAddress)
	if in.Name == "" {
		return models.Target{}, errors.New("target adı zorunludur")
	}
	if len(in.Name) > 100 {
		return models.Target{}, errors.New("target adı en fazla 100 karakter olabilir")
	}
	if err := security.ValidatePrivateIP(in.IPAddress); err != nil {
		return models.Target{}, err
	}
	if in.Port == 0 {
		in.Port = 53
	}
	if in.Port < 1 || in.Port > 65535 {
		return models.Target{}, errors.New("port 1 ile 65535 arasında olmalıdır")
	}
	udp, tcp := true, true
	if in.UDPEnabled != nil {
		udp = *in.UDPEnabled
	}
	if in.TCPEnabled != nil {
		tcp = *in.TCPEnabled
	}
	if !udp && !tcp {
		return models.Target{}, errors.New("UDP veya TCP protokollerinden en az biri etkin olmalıdır")
	}
	t := models.Target{Name: in.Name, IPAddress: in.IPAddress, Port: in.Port, Description: strings.TrimSpace(in.Description), Environment: strings.TrimSpace(in.Environment), UDPEnabled: udp, TCPEnabled: tcp, Tags: normalizeTags(in.Tags)}
	if err := s.repo.CreateTarget(ctx, &t); err != nil {
		return models.Target{}, err
	}
	return t, nil
}
func (s *Service) List(ctx context.Context) ([]models.Target, error) { return s.repo.ListTargets(ctx) }
func (s *Service) Get(ctx context.Context, id int64) (models.Target, error) {
	return s.repo.GetTarget(ctx, id)
}
func (s *Service) Delete(ctx context.Context, id int64) error { return s.repo.DeleteTarget(ctx, id) }
func normalizeTags(tags []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(tags))
	for _, v := range tags {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
