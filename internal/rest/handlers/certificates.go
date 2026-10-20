package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/certimate-go/certimate/internal/certcompat"
	"github.com/certimate-go/certimate/internal/domain"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/domain/dtos"
	"github.com/certimate-go/certimate/internal/rest/resp"
)

type certificateService interface {
	AnalyzeCompatibility(ctx context.Context, req *dtos.CertificateCompatibilityAnalyzeReq) (*certcompat.Result, error)
	BatchCompatibility(ctx context.Context, req *dtos.CertificateCompatibilityBatchReq) (*dtos.CertificateCompatibilityBatchResp, error)
	DownloadCertificate(ctx context.Context, req *dtos.CertificateDownloadReq) (*dtos.CertificateDownloadResp, error)
	RevokeCertificate(ctx context.Context, req *dtos.CertificateRevokeReq) (*dtos.CertificateRevokeResp, error)
}

type CertificatesHandler struct {
	service certificateService
}

func NewCertificatesHandler(router *router.RouterGroup[*core.RequestEvent], service certificateService) {
	handler := &CertificatesHandler{
		service: service,
	}

	group := router.Group("/certificates")
	group.POST("/compatibility/analyze", handler.analyzeCompatibility)
	group.POST("/compatibility/batch", handler.batchCompatibility)
	group.POST("/{certificateId}/download", handler.downloadCertificate)
	group.POST("/{certificateId}/revoke", handler.revokeCertificate)

	group.POST("/{certificateId}/archive", handler.downloadCertificate) // 兼容旧版
}

func (handler *CertificatesHandler) downloadCertificate(e *core.RequestEvent) error {
	req := &dtos.CertificateDownloadReq{}
	req.CertificateId = e.Request.PathValue("certificateId")
	if err := e.BindBody(req); err != nil {
		return resp.Err(e, err)
	}

	res, err := handler.service.DownloadCertificate(e.Request.Context(), req)
	if err != nil {
		return resp.Err(e, err)
	}

	return resp.Ok(e, res)
}

func (handler *CertificatesHandler) revokeCertificate(e *core.RequestEvent) error {
	req := &dtos.CertificateRevokeReq{}
	req.CertificateId = e.Request.PathValue("certificateId")
	if err := e.BindBody(req); err != nil {
		return resp.Err(e, err)
	}

	res, err := handler.service.RevokeCertificate(e.Request.Context(), req)
	if err != nil {
		return resp.Err(e, err)
	}

	return resp.Ok(e, res)
}

// Decode only after bounding the raw body. Returning fixed errors prevents PEM
// or unexpected private-key content from being echoed in API errors or logs.
func bindCompatibilityBody(e *core.RequestEvent, value any, limit int64) error {
	e.Request.Body = http.MaxBytesReader(e.Response, e.Request.Body, limit)
	raw, err := io.ReadAll(e.Request.Body)
	if err != nil {
		return domain.ErrInvalidParams
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return domain.ErrInvalidParams
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return domain.ErrInvalidParams
	}
	return nil
}

func (handler *CertificatesHandler) analyzeCompatibility(e *core.RequestEvent) error {
	req := &dtos.CertificateCompatibilityAnalyzeReq{}
	// PEM newlines may be JSON-escaped; allow overhead but cap the decoded PEM too.
	if err := bindCompatibilityBody(e, req, 2*certcompat.MaxCertificateBytes+1024); err != nil {
		return resp.Err(e, err)
	}
	result, err := handler.service.AnalyzeCompatibility(e.Request.Context(), req)
	if err != nil {
		return resp.Err(e, err)
	}
	return resp.Ok(e, result)
}

func (handler *CertificatesHandler) batchCompatibility(e *core.RequestEvent) error {
	req := &dtos.CertificateCompatibilityBatchReq{}
	if err := bindCompatibilityBody(e, req, 16*1024); err != nil {
		return resp.Err(e, err)
	}
	result, err := handler.service.BatchCompatibility(e.Request.Context(), req)
	if err != nil {
		return resp.Err(e, err)
	}
	return resp.Ok(e, result)
}
