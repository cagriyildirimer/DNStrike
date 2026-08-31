package target

import (
	"context"
	"github.com/dnstrike/dnstrike/pkg/models"
	"testing"
)

type fakeRepo struct{ saved *models.Target }

func (f *fakeRepo) CreateTarget(_ context.Context, t *models.Target) error {
	t.ID = 1
	f.saved = t
	return nil
}
func (f *fakeRepo) ListTargets(context.Context) ([]models.Target, error) { return nil, nil }
func (f *fakeRepo) GetTarget(context.Context, int64) (models.Target, error) {
	return models.Target{}, nil
}
func (f *fakeRepo) DeleteTarget(context.Context, int64) error { return nil }

func TestCreateAppliesSafeDefaults(t *testing.T) {
	repo := &fakeRepo{}
	service := NewService(repo)
	got, err := service.Create(context.Background(), models.CreateTargetInput{Name: " Lab DNS ", IPAddress: "127.0.0.1", Tags: []string{"lab", " lab ", ""}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != 53 || !got.UDPEnabled || !got.TCPEnabled {
		t.Fatalf("unsafe defaults: %#v", got)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "lab" {
		t.Fatalf("tags not normalized: %#v", got.Tags)
	}
}
func TestCreateRejectsPublicIP(t *testing.T) {
	_, err := NewService(&fakeRepo{}).Create(context.Background(), models.CreateTargetInput{Name: "Public", IPAddress: "8.8.8.8"})
	if err == nil {
		t.Fatal("expected public IP rejection")
	}
}
func TestCreateRequiresProtocol(t *testing.T) {
	f := false
	_, err := NewService(&fakeRepo{}).Create(context.Background(), models.CreateTargetInput{Name: "Lab", IPAddress: "127.0.0.1", UDPEnabled: &f, TCPEnabled: &f})
	if err == nil {
		t.Fatal("expected protocol validation error")
	}
}
