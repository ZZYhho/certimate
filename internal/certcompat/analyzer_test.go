package certcompat

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func issueTestCert(t *testing.T, name string, parent *testCert, ca bool, modify func(*x509.Certificate)) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: testNow.Add(-24 * time.Hour), NotAfter: testNow.Add(365 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{name}, SignatureAlgorithm: x509.ECDSAWithSHA256}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.ExtKeyUsage = nil
	}
	if modify != nil {
		modify(template)
	}
	issuer, issuerKey := template, key
	if parent != nil {
		issuer = parent.cert
		issuerKey = parent.key
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return testCert{cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))}
}

func testAnalyzer(profiles ...Profile) *Analyzer {
	a := NewAnalyzer("test", profiles)
	a.now = func() time.Time { return testNow }
	return a
}

func TestCompatibilityTrustVersionsAndAlternativePaths(t *testing.T) {
	root := issueTestCert(t, "public root", nil, true, nil)
	other := issueTestCert(t, "other root", nil, true, nil)
	issuer := issueTestCert(t, "issuer", &root, true, nil)
	leaf := issueTestCert(t, "example.com", &issuer, false, nil)
	tests := []struct {
		name      string
		profiles  []Profile
		minimum   string
		supported int
	}{
		{"suffix", []Profile{{Version: "4.1", Roots: []*x509.Certificate{other.cert}}, {Version: "5.1", Roots: []*x509.Certificate{root.cert}}, {Version: "17", Roots: []*x509.Certificate{root.cert}}}, "5.1", 2},
		{"discontinuous", []Profile{{Version: "4.1", Roots: []*x509.Certificate{root.cert}}, {Version: "5.1", Roots: []*x509.Certificate{other.cert}}, {Version: "17", Roots: []*x509.Certificate{root.cert}}}, "17", 2},
		{"no suffix", []Profile{{Version: "4.1", Roots: []*x509.Certificate{root.cert}}, {Version: "17", Roots: []*x509.Certificate{other.cert}}}, "", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := testAnalyzer(tc.profiles...).Analyze(leaf.pem + issuer.pem)
			if result.Status != "compatible" || result.MinimumVersion != tc.minimum || len(result.SupportedVersions) != tc.supported {
				t.Fatalf("unexpected result %+v", result)
			}
			if result.Scope != Scope || !result.EvaluatedAt.Equal(testNow) || result.Profiles[0].Roots[0].Name != "public root" {
				t.Fatalf("missing evidence %+v", result)
			}
		})
	}
	// Two certificates share an issuer name/key, but one alternative is expired.
	expiredIssuer := issueTestCertWithSameKey(t, issuer, &root, testNow.Add(-time.Hour))
	result := testAnalyzer(Profile{Version: "17", Roots: []*x509.Certificate{root.cert}}).Analyze(leaf.pem + expiredIssuer + issuer.pem)
	if result.Status != "compatible" {
		t.Fatalf("valid alternative rejected: %+v", result)
	}
}

func issueTestCertWithSameKey(t *testing.T, source testCert, parent *testCert, notAfter time.Time) string {
	t.Helper()
	template := *source.cert
	template.NotAfter = notAfter
	raw, err := x509.CreateCertificate(rand.Reader, &template, parent.cert, &source.key.PublicKey, parent.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
}

func TestCompatibilityFailureReasonsAndUploadedRoots(t *testing.T) {
	root := issueTestCert(t, "trusted", nil, true, nil)
	private := issueTestCert(t, "private", nil, true, nil)
	issuer := issueTestCert(t, "intermediate", &root, true, nil)
	leaf := issueTestCert(t, "example.com", &issuer, false, nil)
	privateLeaf := issueTestCert(t, "private.example", &private, false, nil)
	expired := issueTestCert(t, "expired.example", &root, false, func(c *x509.Certificate) { c.NotAfter = testNow.Add(-time.Hour) })
	future := issueTestCert(t, "future.example", &root, false, func(c *x509.Certificate) { c.NotBefore = testNow.Add(time.Hour) })
	client := issueTestCert(t, "client.example", &root, false, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} })
	wrongIssuer := issueTestCert(t, "intermediate", &root, true, nil)
	invalidRaw := append([]byte{}, leaf.cert.Raw...)
	invalidRaw[len(invalidRaw)-1] ^= 1
	invalidSignature := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: invalidRaw}))
	tests := []struct{ name, chain, status, reason string }{
		{"missing intermediate", leaf.pem, "unknown", "incomplete_chain"},
		{"uploaded private root", privateLeaf.pem + private.pem, "not_trusted", "root_not_in_system_store"},
		{"private self signed", private.pem, "not_trusted", "root_not_in_system_store"},
		{"expired", expired.pem, "invalid", "expired"},
		{"future", future.pem, "invalid", "not_yet_valid"},
		{"client auth only", client.pem, "invalid", "invalid_server_auth_usage"},
		{"wrong issuer key", leaf.pem + wrongIssuer.pem, "invalid", "invalid_signature"},
		{"invalid signature", invalidSignature + issuer.pem, "invalid", "invalid_signature"},
		{"bad pem", "secret private key", "invalid", "invalid_pem"},
		{"trailing junk", leaf.pem + "junk", "invalid", "invalid_pem"},
		{"oversized", strings.Repeat("x", MaxCertificateBytes+1), "invalid", "certificate_too_large"},
		{"certificate count", strings.Repeat(root.pem, MaxCertificates+1), "invalid", "too_many_certificates"},
	}
	a := testAnalyzer(Profile{Version: "17", Roots: []*x509.Certificate{root.cert}})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := a.Analyze(tc.chain)
			if r.Status != tc.status || r.Reason != tc.reason {
				t.Fatalf("got %+v; want %s %s", r, tc.status, tc.reason)
			}
		})
	}
}

func TestConservativeAlgorithmsAndTrustAnchorDates(t *testing.T) {
	root := issueTestCert(t, "expired anchor", nil, true, func(c *x509.Certificate) { c.NotAfter = testNow.Add(-time.Hour) })
	leaf := issueTestCert(t, "example.com", &root, false, nil)
	r := testAnalyzer(Profile{Version: "17", Roots: []*x509.Certificate{root.cert}}).Analyze(leaf.pem)
	if r.Status != "unknown" || r.Reason != "trust_anchor_validity_not_emulated" {
		t.Fatalf("unexpected anchor expiry result %+v", r)
	}
	// Signature support cannot be inferred just from a successful Go verifier.
	if !unsupportedCertificate(&x509.Certificate{PublicKeyAlgorithm: x509.RSA, SignatureAlgorithm: x509.SHA256WithRSAPSS}) {
		t.Fatal("PSS must remain unknown")
	}
	if !unsupportedCertificate(&x509.Certificate{PublicKeyAlgorithm: x509.Ed25519, SignatureAlgorithm: x509.PureEd25519}) {
		t.Fatal("Ed25519 must remain unknown")
	}
	if !unsupportedCertificate(&x509.Certificate{PublicKeyAlgorithm: x509.RSA, SignatureAlgorithm: x509.SHA1WithRSA}) {
		t.Fatal("SHA1 must remain unknown")
	}
}

func TestEmbeddedTrustData(t *testing.T) {
	a, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]bool{}
	for _, profile := range a.profiles {
		versions[profile.version] = true
		if len(profile.roots.Subjects()) == 0 {
			t.Fatalf("empty trust store %s", profile.version)
		}
	}
	for _, version := range []string{"4.1", "5.1", "7.1.1", "17"} {
		if !versions[version] {
			t.Errorf("missing profile %s", version)
		}
	}
	if len(a.roots) < 100 || a.version == "" {
		t.Fatalf("invalid embedded data %d roots", len(a.roots))
	}
}

func TestUnparseableHistoricalAnchorsRemainConservative(t *testing.T) {
	root := issueTestCert(t, "trusted", nil, true, nil)
	other := issueTestCert(t, "other", nil, true, nil)
	leaf := issueTestCert(t, "example.com", &root, false, nil)
	a := testAnalyzer(
		Profile{Version: "4.1", Roots: []*x509.Certificate{other.cert}, UnsupportedRoots: 1},
		Profile{Version: "17", Roots: []*x509.Certificate{root.cert}},
	)
	r := a.Analyze(leaf.pem)
	if r.Profiles[0].Status != "unknown" || r.Profiles[0].Reason != "unsupported_trust_anchor" || r.Profiles[1].Status != "trusted" || r.MinimumVersion != "17" {
		t.Fatalf("unparseable anchor must not give false rejection or suppress valid path: %+v", r)
	}
	embedded, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, profile := range embedded.profiles {
		if profile.unsupportedRoots > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected original historical negative-serial AOSP roots to remain unsupported")
	}
}

func TestSelfIssuedCertificateCanUseDifferentKeyParent(t *testing.T) {
	root := issueTestCert(t, "shared name", nil, true, nil)
	leaf := issueTestCert(t, "shared name", &root, false, nil)
	if !bytes.Equal(leaf.cert.RawSubject, leaf.cert.RawIssuer) || leaf.cert.CheckSignature(leaf.cert.SignatureAlgorithm, leaf.cert.RawTBSCertificate, leaf.cert.Signature) == nil {
		t.Fatal("test must use self-issued leaf with a different-key issuer")
	}
	r := testAnalyzer(Profile{Version: "17", Roots: []*x509.Certificate{root.cert}}).Analyze(leaf.pem + root.pem)
	if r.Status != "compatible" || r.Profiles[0].Status != "trusted" {
		t.Fatalf("valid self-issued path rejected: %+v", r)
	}
	if !r.Estimated {
		t.Fatal("result must identify the estimate")
	}
}

func TestUploadedHistoricalNegativeSerialRemainsUnknown(t *testing.T) {
	legacy, err := embeddedData.ReadFile("data/roots/88497f01602f3154246ae28c4d5aef10f1d87ebb76626f4ae0b7f95ba7968799.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(legacy)
	if _, err := x509.ParseCertificate(block.Bytes); err == nil || err.Error() != "x509: negative serial number" {
		t.Fatalf("expected historical negative serial fixture, got %v", err)
	}
	a := testAnalyzer(Profile{Version: "17"})
	for _, value := range []string{string(legacy), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("malformed DER")}))} {
		r := a.Analyze(value)
		if !r.Estimated {
			t.Fatal("every result must identify the estimate")
		}
		if value == string(legacy) {
			if r.Status != "unknown" || r.Reason != "unsupported_certificate_format" {
				t.Fatalf("unsupported legacy format was called invalid: %+v", r)
			}
		} else if r.Status != "invalid" || r.Reason != "invalid_certificate" {
			t.Fatalf("malformed DER was called unsupported: %+v", r)
		}
	}
	if !a.Unavailable("certificate_not_found").Estimated {
		t.Fatal("unavailable results must identify the estimate")
	}
}

func TestEmbeddedProfilesDoNotObscureCompletePrivateChains(t *testing.T) {
	a, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	fixed := *a
	fixed.now = func() time.Time { return testNow }
	a = &fixed
	private := issueTestCert(t, "private-root.example", nil, true, nil)
	leaf := issueTestCert(t, "private.example", &private, false, nil)
	for _, chain := range []string{private.pem, leaf.pem + private.pem} {
		r := a.Analyze(chain)
		if r.Status != "not_trusted" || r.Reason != "root_not_in_system_store" {
			t.Fatalf("complete private chain obscured by unsupported historical anchor: %+v", r)
		}
		for _, profile := range r.Profiles {
			if profile.Status != "not_trusted" {
				t.Fatalf("private chain must be explicitly untrusted on %s: %+v", profile.Version, profile)
			}
		}
	}
}

func TestUnparseableAnchorSubjectMatchingIsConservative(t *testing.T) {
	private := issueTestCert(t, "private-root.example", nil, true, nil)
	leaf := issueTestCert(t, "private.example", &private, false, nil)
	for _, subject := range [][]byte{private.cert.RawSubject, []byte("unrelated subject")} {
		a := testAnalyzer(Profile{Version: "4.1", UnsupportedRoots: 1, UnsupportedRootSubjects: [][]byte{subject}})
		r := a.Analyze(leaf.pem + private.pem)
		if bytes.Equal(subject, private.cert.RawSubject) {
			if r.Status != "unknown" || r.Reason != "unsupported_trust_anchor" {
				t.Fatalf("same subject could be a system anchor with different DER: %+v", r)
			}
		} else if r.Status != "not_trusted" {
			t.Fatalf("unrelated skipped anchor cannot affect private path: %+v", r)
		}
	}
	for _, cert := range []testCert{private, leaf} {
		if got := extractSubjectDER(cert.cert.Raw); !bytes.Equal(got, cert.cert.RawSubject) {
			t.Fatalf("raw subject extraction changed DER: %x vs %x", got, cert.cert.RawSubject)
		}
	}
	if extractSubjectDER([]byte("bad DER")) != nil {
		t.Fatal("malformed DER must retain unknown metadata")
	}
	legacy, err := embeddedData.ReadFile("data/roots/88497f01602f3154246ae28c4d5aef10f1d87ebb76626f4ae0b7f95ba7968799.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(legacy)
	if len(extractSubjectDER(block.Bytes)) == 0 {
		t.Fatal("negative serial must not prevent raw subject extraction")
	}
}

func TestSkippedAnchorCanBeAlternativeToSuppliedWrongIssuer(t *testing.T) {
	correct := issueTestCert(t, "same-root-subject", nil, true, nil)
	wrong := issueTestCert(t, "same-root-subject", nil, true, nil)
	leaf := issueTestCert(t, "example.com", &correct, false, nil)
	for _, subject := range [][]byte{correct.cert.RawSubject, []byte("unrelated subject")} {
		a := testAnalyzer(Profile{Version: "4.1", UnsupportedRoots: 1, UnsupportedRootSubjects: [][]byte{subject}})
		r := a.Analyze(leaf.pem + wrong.pem)
		if bytes.Equal(subject, correct.cert.RawSubject) {
			if r.Status != "unknown" || r.Reason != "unsupported_trust_anchor" {
				t.Fatalf("a skipped same-subject anchor may validate the leaf: %+v", r)
			}
		} else if r.Status != "invalid" || r.Reason != "invalid_signature" {
			t.Fatalf("unrelated skipped anchor must not conceal known invalid signature: %+v", r)
		}
	}
}
