package certificate

import (
	"context"

	"github.com/pocketbase/dbx"

	"github.com/certimate-go/certimate/internal/domain"
)

type acmeAccountRepository interface {
	GetByCAAndAcctUrl(ctx context.Context, ca string, acctUrl string) (*domain.ACMEAccount, error)
}

type certificateRepository interface {
	GetCertificatePEMsByIds(ctx context.Context, ids []string) (map[string]string, error)
	GetById(ctx context.Context, id string) (*domain.Certificate, error)
	Save(ctx context.Context, certificate *domain.Certificate) (*domain.Certificate, error)
	DeleteWithExprs(ctx context.Context, exprs ...dbx.Expression) (int, error)
}
