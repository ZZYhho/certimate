package certificate

import (
	"context"
	"strings"

	"github.com/certimate-go/certimate/internal/certcompat"
	"github.com/certimate-go/certimate/internal/domain"
	"github.com/certimate-go/certimate/internal/domain/dtos"
)

func (s *CertificateService) AnalyzeCompatibility(ctx context.Context, req *dtos.CertificateCompatibilityAnalyzeReq) (*certcompat.Result, error) {
	if req == nil || len(req.Certificate) > certcompat.MaxCertificateBytes || strings.TrimSpace(req.Certificate) == "" {
		return nil, domain.ErrInvalidParams
	}
	a, err := certcompat.Default()
	if err != nil {
		return nil, err
	}
	result := a.Analyze(req.Certificate)
	return &result, nil
}

func (s *CertificateService) BatchCompatibility(ctx context.Context, req *dtos.CertificateCompatibilityBatchReq) (*dtos.CertificateCompatibilityBatchResp, error) {
	if req == nil || len(req.CertificateIds) == 0 || len(req.CertificateIds) > 100 {
		return nil, domain.ErrInvalidParams
	}
	ids := make([]string, 0, len(req.CertificateIds))
	seen := map[string]bool{}
	for _, id := range req.CertificateIds {
		if len(id) == 0 || len(id) > 100 || strings.TrimSpace(id) != id {
			return nil, domain.ErrInvalidParams
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	a, err := certcompat.Default()
	if err != nil {
		return nil, err
	}
	certificates, err := s.certificateRepo.GetCertificatePEMsByIds(ctx, ids)
	if err != nil {
		return nil, err
	}
	response := &dtos.CertificateCompatibilityBatchResp{Results: make(map[string]certcompat.Result, len(ids))}
	for _, id := range ids {
		if value, ok := certificates[id]; ok {
			response.Results[id] = a.Analyze(value)
		} else {
			response.Results[id] = a.Unavailable("certificate_not_found")
		}
	}
	return response, nil
}
