package dtos

import (
	"github.com/certimate-go/certimate/internal/certcompat"
	"github.com/certimate-go/certimate/internal/domain"
)

type CertificateDownloadReq struct {
	CertificateId string                       `json:"-"`
	FileFormat    domain.CertificateFormatType `json:"fileFormat"`
	PfxPassword   string                       `json:"pfxPassword,omitempty"`
	PfxEncoder    string                       `json:"pfxEncoder,omitempty"`
	JksAlias      string                       `json:"jksAlias,omitempty"`
	JksKeypass    string                       `json:"jksKeypass,omitempty"`
	JksStorepass  string                       `json:"jksStorepass,omitempty"`
}

type CertificateDownloadResp struct {
	ZipBytes []byte `json:"zipBytes"`
}

type CertificateRevokeReq struct {
	CertificateId string `json:"-"`
}

type CertificateRevokeResp struct{}

type CertificateCompatibilityAnalyzeReq struct {
	Certificate string `json:"certificate"`
}

type CertificateCompatibilityBatchReq struct {
	CertificateIds []string `json:"certificateIds"`
}

type CertificateCompatibilityBatchResp struct {
	Results map[string]certcompat.Result `json:"results"`
}
