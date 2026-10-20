package certificate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pocketbase/dbx"

	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/domain/dtos"
)

type compatibilityRepository struct {
	calls int
	ids   []string
}

func (r *compatibilityRepository) GetById(context.Context, string) (*domain.Certificate, error) {
	panic("must not fetch private key")
}

func (r *compatibilityRepository) Save(context.Context, *domain.Certificate) (*domain.Certificate, error) {
	panic("unexpected")
}

func (r *compatibilityRepository) DeleteWithExprs(context.Context, ...dbx.Expression) (int, error) {
	panic("unexpected")
}

func (r *compatibilityRepository) GetCertificatePEMsByIds(_ context.Context, ids []string) (map[string]string, error) {
	r.calls++
	r.ids = ids
	return map[string]string{"live": "not PEM"}, nil
}

func TestBatchCompatibilityLimitsMissingAndPrivacy(t *testing.T) {
	repo := &compatibilityRepository{}
	service := NewCertificateService(nil, repo)
	for _, req := range []*dtos.CertificateCompatibilityBatchReq{nil, {}, {CertificateIds: make([]string, 101)}, {CertificateIds: []string{""}}, {CertificateIds: []string{" spaced "}}} {
		if _, err := service.BatchCompatibility(context.Background(), req); err != domain.ErrInvalidParams {
			t.Fatalf("invalid request accepted: %v", err)
		}
	}
	if repo.calls != 0 {
		t.Fatal("invalid requests queried database")
	}
	result, err := service.BatchCompatibility(context.Background(), &dtos.CertificateCompatibilityBatchReq{CertificateIds: []string{"live", "deleted", "live"}})
	if err != nil {
		t.Fatal(err)
	}
	if repo.calls != 1 || len(repo.ids) != 2 {
		t.Fatalf("expected one deduplicated bulk query: %+v", repo)
	}
	if result.Results["live"].Status != "invalid" || result.Results["deleted"].Reason != "certificate_not_found" || len(result.Results) != 2 {
		t.Fatalf("wrong partial batch %+v", result)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"privateKey", "not PEM", "BEGIN CERTIFICATE"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("public-only response leaked %s", secret)
		}
	}
}
