package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"

	"github.com/certimate-go/certimate/internal/certcompat"
	"github.com/certimate-go/certimate/internal/domain/dtos"
)

type compatibilityHandlerService struct{ calls int }

func (s *compatibilityHandlerService) DownloadCertificate(context.Context, *dtos.CertificateDownloadReq) (*dtos.CertificateDownloadResp, error) {
	panic("unexpected")
}

func (s *compatibilityHandlerService) RevokeCertificate(context.Context, *dtos.CertificateRevokeReq) (*dtos.CertificateRevokeResp, error) {
	panic("unexpected")
}

func (s *compatibilityHandlerService) AnalyzeCompatibility(context.Context, *dtos.CertificateCompatibilityAnalyzeReq) (*certcompat.Result, error) {
	s.calls++
	return &certcompat.Result{Status: "unknown", Reason: "incomplete_chain"}, nil
}

func (s *compatibilityHandlerService) BatchCompatibility(context.Context, *dtos.CertificateCompatibilityBatchReq) (*dtos.CertificateCompatibilityBatchResp, error) {
	s.calls++
	return &dtos.CertificateCompatibilityBatchResp{Results: map[string]certcompat.Result{}}, nil
}

func TestCompatibilityHandlerAuthenticationAndBoundedBodies(t *testing.T) {
	for _, tc := range []struct {
		name, path, body    string
		admin               bool
		code, status, calls int
	}{
		{"guest analyze", "analyze", `{"certificate":"public"}`, false, 0, 401, 0},
		{"guest batch", "batch", `{"certificateIds":["id"]}`, false, 0, 401, 0},
		{"authenticated analyze", "analyze", `{"certificate":"public"}`, true, 0, 200, 1},
		{"authenticated batch", "batch", `{"certificateIds":["id"]}`, true, 0, 200, 1},
		{"oversize analyze", "analyze", `{"certificate":"` + strings.Repeat("x", 2*certcompat.MaxCertificateBytes+1024) + `"}`, true, 400, 200, 0},
		{"oversize batch", "batch", `{"certificateIds":["` + strings.Repeat("x", 16*1024) + `"]}`, true, 400, 200, 0},
		{"private key field rejected", "analyze", `{"certificate":"public","privateKey":"secret-value"}`, true, 400, 200, 0},
		{"multiple json values", "analyze", `{} {}`, true, 400, 200, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &compatibilityHandlerService{}
			r := router.NewRouter(func(w http.ResponseWriter, req *http.Request) (*core.RequestEvent, router.EventCleanupFunc) {
				event := &core.RequestEvent{Event: router.Event{Response: w, Request: req}}
				if tc.admin {
					event.Auth = core.NewRecord(core.NewAuthCollection(core.CollectionNameSuperusers))
				}
				return event, nil
			})
			api := r.Group("/api")
			api.Bind(apis.RequireSuperuserAuth())
			NewCertificatesHandler(api, service)
			mux, err := r.BuildMux()
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/certificates/compatibility/"+tc.path, strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			mux.ServeHTTP(recorder, request)
			if recorder.Code != tc.status || service.calls != tc.calls {
				t.Fatalf("status %d calls %d body %s", recorder.Code, service.calls, recorder.Body.String())
			}
			if tc.admin {
				var body struct {
					Code int `json:"code"`
				}
				if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Code != tc.code {
					t.Fatalf("got response %s", recorder.Body.String())
				}
			}
			if strings.Contains(recorder.Body.String(), "secret-value") || strings.Contains(recorder.Body.String(), "privateKey") {
				t.Fatal("request secret echoed in response")
			}
		})
	}
}
