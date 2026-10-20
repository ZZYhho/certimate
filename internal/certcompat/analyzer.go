// Package certcompat estimates certificate-chain trust against versioned Android
// system roots. It does not emulate Android TLS or application trust policies.
package certcompat

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sort"
	"sync"
	"time"
)

const (
	MaxCertificateBytes = 256 * 1024
	MaxCertificates     = 32
	Scope               = "android_system_roots"
)

type Root struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
}

type ProfileResult struct {
	Version string `json:"version"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Roots   []Root `json:"roots"`
}

type Result struct {
	Status            string          `json:"status"`
	Reason            string          `json:"reason"`
	MinimumVersion    string          `json:"minimumVersion,omitempty"`
	SupportedVersions []string        `json:"supportedVersions"`
	Profiles          []ProfileResult `json:"profiles"`
	DataVersion       string          `json:"dataVersion"`
	EvaluatedAt       time.Time       `json:"evaluatedAt"`
	Scope             string          `json:"scope"`
	Estimated         bool            `json:"estimated"`
	OldestVersion     string          `json:"oldestVersion,omitempty"`
	NewestVersion     string          `json:"newestVersion,omitempty"`
}

// Profile is ordered by Android release, oldest first. Roots must come from the
// selected AOSP source, never from the submitted certificate chain.
type Profile struct {
	Version                 string
	Roots                   []*x509.Certificate
	UnsupportedRoots        int
	UnsupportedRootSubjects [][]byte
}

type compiledProfile struct {
	version                 string
	roots                   *x509.CertPool
	unsupportedRoots        int
	unsupportedRootSubjects [][]byte
}

type Analyzer struct {
	version  string
	profiles []compiledProfile
	roots    []*x509.Certificate
	now      func() time.Time
}

func NewAnalyzer(version string, profiles []Profile) *Analyzer {
	a := &Analyzer{version: version, now: time.Now}
	seen := make(map[string]bool)
	for _, profile := range profiles {
		pool := x509.NewCertPool()
		for _, root := range profile.Roots {
			pool.AddCert(root)
			fp := fingerprint(root)
			if !seen[fp] {
				a.roots = append(a.roots, root)
				seen[fp] = true
			}
		}
		a.profiles = append(a.profiles, compiledProfile{version: profile.Version, roots: pool, unsupportedRoots: profile.UnsupportedRoots, unsupportedRootSubjects: profile.UnsupportedRootSubjects})
	}
	return a
}

func (a *Analyzer) Unavailable(reason string) Result {
	r := Result{Status: "unknown", Reason: reason, SupportedVersions: []string{}, Profiles: []ProfileResult{}, DataVersion: a.version, EvaluatedAt: a.now().UTC(), Scope: Scope, Estimated: true}
	if len(a.profiles) > 0 {
		r.OldestVersion = a.profiles[0].version
		r.NewestVersion = a.profiles[len(a.profiles)-1].version
	}
	return r
}

func (a *Analyzer) Analyze(certificate string) Result {
	r := a.Unavailable("incomplete_chain")
	certs, reason := parseChain(certificate)
	if reason != "" {
		r.Status = "invalid"
		if reason == "unsupported_certificate_format" {
			r.Status = "unknown"
		}
		r.Reason = reason
		return r
	}
	now := r.EvaluatedAt
	leaf := certs[0]
	if now.Before(leaf.NotBefore) {
		r.Status = "invalid"
		r.Reason = "not_yet_valid"
		return r
	}
	if now.After(leaf.NotAfter) {
		r.Status = "invalid"
		r.Reason = "expired"
		return r
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	options := x509.VerifyOptions{Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	// This pool diagnoses a complete but untrusted chain. A successful verification
	// here can only produce not_trusted; uploaded roots never grant compatibility.
	diagnostic := x509.NewCertPool()
	for _, cert := range a.roots {
		diagnostic.AddCert(cert)
	}
	for _, cert := range certs {
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
			diagnostic.AddCert(cert)
		}
	}
	diagnosticOptions := options
	diagnosticOptions.Roots = diagnostic
	fallbackChains, fallbackErr := leaf.Verify(diagnosticOptions)
	fallbackStatus, fallbackReason := classifyFailure(fallbackErr, certs, a.roots, now)
	if fallbackErr == nil {
		fallbackStatus = "not_trusted"
		fallbackReason = "root_not_in_system_store"
	}
	for _, profile := range a.profiles {
		options.Roots = profile.roots
		chains, err := leaf.Verify(options)
		p := ProfileResult{Version: profile.version, Status: fallbackStatus, Reason: fallbackReason, Roots: []Root{}}
		if err == nil {
			p.Status = "trusted"
			p.Reason = "trusted_system_root"
			p.Roots = chainRoots(chains)
			if unsupportedChain(chains) {
				p.Status = "unknown"
				p.Reason = "unsupported_algorithm"
			}
		} else {
			// Prefer complete-path diagnostics over the profile's unknown-authority
			// error, which can conceal missing intermediates or invalid signatures.
			if fallbackErr == nil {
				p.Roots = chainRoots(fallbackChains)
				if unsupportedChain(fallbackChains) {
					p.Status = "unknown"
					p.Reason = "unsupported_algorithm"
				}
			}
			var invalid x509.CertificateInvalidError
			if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
				p.Status = "invalid"
				p.Reason = validityReason(invalid.Cert, now)
				if isRoot(invalid.Cert, a.roots) {
					p.Status = "unknown"
					p.Reason = "trust_anchor_validity_not_emulated"
				}
			}
		}
		if err != nil && (p.Status == "not_trusted" || p.Status == "invalid") && unsupportedAnchorCouldMatch(profile, certs) {
			p.Status = "unknown"
			p.Reason = "unsupported_trust_anchor"
		}
		r.Profiles = append(r.Profiles, p)
		if p.Status == "trusted" {
			r.SupportedVersions = append(r.SupportedVersions, p.Version)
		}
	}
	summarize(&r)
	return r
}

// A rejected historical trust anchor can only matter to a supplied path when
// its raw subject matches an issuer in that path. Missing metadata keeps the
// outcome conservative. This never rewrites DER or treats supplied roots as
// trusted; even a same-DN different-key candidate remains unknown.
func unsupportedAnchorCouldMatch(profile compiledProfile, certs []*x509.Certificate) bool {
	if profile.unsupportedRoots > len(profile.unsupportedRootSubjects) {
		return true
	}
	for _, subject := range profile.unsupportedRootSubjects {
		for _, cert := range certs {
			if bytes.Equal(cert.RawIssuer, subject) {
				return true
			}
		}
	}
	return false
}

func parseChain(value string) ([]*x509.Certificate, string) {
	if len(value) > MaxCertificateBytes {
		return nil, "certificate_too_large"
	}
	rest := []byte(value)
	var certs []*x509.Certificate
	seen := map[string]bool{}
	count := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		rest = bytes.TrimSpace(rest)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, "invalid_pem"
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return nil, "invalid_pem"
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			if err.Error() == "x509: negative serial number" {
				return nil, "unsupported_certificate_format"
			}
			return nil, "invalid_certificate"
		}
		count++
		if count > MaxCertificates {
			return nil, "too_many_certificates"
		}
		if !seen[fingerprint(cert)] {
			certs = append(certs, cert)
			seen[fingerprint(cert)] = true
		}
		rest = remaining
	}
	if len(certs) == 0 {
		return nil, "invalid_pem"
	}
	return certs, ""
}

func classifyFailure(err error, certs, systemRoots []*x509.Certificate, now time.Time) (string, string) {
	if err == nil {
		return "not_trusted", "root_not_in_system_store"
	}
	var insecure x509.InsecureAlgorithmError
	if errors.As(err, &insecure) || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		return "unknown", "unsupported_algorithm"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		switch invalid.Reason {
		case x509.Expired:
			if isRoot(invalid.Cert, systemRoots) {
				return "unknown", "trust_anchor_validity_not_emulated"
			}
			return "invalid", validityReason(invalid.Cert, now)
		case x509.IncompatibleUsage:
			return "invalid", "invalid_server_auth_usage"
		default:
			return "invalid", "invalid_chain_constraints"
		}
	}
	var unhandled x509.UnhandledCriticalExtension
	if errors.As(err, &unhandled) {
		return "unknown", "unsupported_critical_extension"
	}
	candidates := append(append([]*x509.Certificate{}, certs[1:]...), systemRoots...)
	status, reason := inspectPath(certs[0], candidates, map[string]bool{}, 0, new(int))
	return status, reason
}

func inspectPath(cert *x509.Certificate, candidates []*x509.Certificate, seen map[string]bool, depth int, work *int) (string, string) {
	*work++
	if *work > 256 {
		return "unknown", "analysis_limit"
	}
	if depth > MaxCertificates || seen[fingerprint(cert)] {
		return "invalid", "invalid_chain_constraints"
	}
	if unsupportedCertificate(cert) {
		return "unknown", "unsupported_algorithm"
	}
	// A matching issuer and subject DN can also identify a self-issued
	// certificate signed by a different key. Only a valid self-signature proves
	// it is self-signed; otherwise continue searching the supplied issuers.
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
		return "not_trusted", "root_not_in_system_store"
	}
	nextSeen := make(map[string]bool, len(seen)+1)
	for key, value := range seen {
		nextSeen[key] = value
	}
	nextSeen[fingerprint(cert)] = true
	matched := false
	status, reason := "invalid", "invalid_signature"
	for _, parent := range candidates {
		if !bytes.Equal(cert.RawIssuer, parent.RawSubject) {
			continue
		}
		matched = true
		*work++
		if *work > 256 {
			return "unknown", "analysis_limit"
		}
		err := cert.CheckSignatureFrom(parent)
		if err != nil {
			var insecure x509.InsecureAlgorithmError
			if errors.As(err, &insecure) || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
				status = "unknown"
				reason = "unsupported_algorithm"
			}
			continue
		}
		s, r := inspectPath(parent, candidates, nextSeen, depth+1, work)
		if s == "not_trusted" {
			return s, r
		}
		if s == "unknown" {
			status = s
			reason = r
		}
	}
	if !matched {
		return "unknown", "incomplete_chain"
	}
	return status, reason
}

func isRoot(cert *x509.Certificate, roots []*x509.Certificate) bool {
	for _, root := range roots {
		if bytes.Equal(root.Raw, cert.Raw) {
			return true
		}
	}
	return false
}

func validityReason(cert *x509.Certificate, now time.Time) string {
	if now.Before(cert.NotBefore) {
		return "not_yet_valid"
	}
	return "expired"
}

func unsupportedCertificate(cert *x509.Certificate) bool {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA, x509.ECDSA:
	default:
		return true
	}
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return false
	default:
		return true
	}
}

func unsupportedChain(chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		supported := true
		// A trust anchor's self-signature is not verified by the trust path.
		for i, cert := range chain {
			if i < len(chain)-1 && unsupportedCertificate(cert) {
				supported = false
				break
			}
		}
		if supported {
			return false
		}
	}
	return true
}

func chainRoots(chains [][]*x509.Certificate) []Root {
	roots := []Root{}
	seen := map[string]bool{}
	for _, chain := range chains {
		cert := chain[len(chain)-1]
		fp := fingerprint(cert)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		name := cert.Subject.CommonName
		if name == "" {
			name = cert.Subject.String()
		}
		roots = append(roots, Root{fp, name})
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Fingerprint < roots[j].Fingerprint })
	return roots
}

func fingerprint(cert *x509.Certificate) string {
	fp := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fp[:])
}

func summarize(r *Result) {
	if len(r.Profiles) == 0 {
		return
	}
	for i := len(r.Profiles) - 1; i >= 0; i-- {
		if r.Profiles[i].Status != "trusted" {
			break
		}
		r.MinimumVersion = r.Profiles[i].Version
	}
	if len(r.SupportedVersions) > 0 {
		r.Status = "compatible"
		r.Reason = "supported_versions"
		return
	}
	r.Status = "not_trusted"
	r.Reason = "root_not_in_system_store"
	for _, p := range r.Profiles {
		if p.Status == "invalid" {
			r.Status = p.Status
			r.Reason = p.Reason
			return
		}
		if p.Status == "unknown" {
			r.Status = p.Status
			r.Reason = p.Reason
		}
	}
}

var (
	defaultOnce     sync.Once
	defaultAnalyzer *Analyzer
	defaultError    error
)

func Default() (*Analyzer, error) {
	defaultOnce.Do(func() { defaultAnalyzer, defaultError = loadEmbedded() })
	return defaultAnalyzer, defaultError
}
