package certcompat

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

//go:embed data/profiles.json data/roots/*.pem
var embeddedData embed.FS

func loadEmbedded() (*Analyzer, error) {
	var manifest struct {
		Version  string `json:"version"`
		Profiles []struct {
			Version string   `json:"version"`
			Roots   []string `json:"roots"`
		} `json:"profiles"`
	}
	raw, err := embeddedData.ReadFile("data/profiles.json")
	if err != nil {
		return nil, fmt.Errorf("Android trust data is unavailable")
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Version == "" || len(manifest.Profiles) == 0 {
		return nil, fmt.Errorf("Android trust manifest is invalid")
	}
	profiles := make([]Profile, 0, len(manifest.Profiles))
	cache := map[string]*x509.Certificate{}
	unsupportedSubjects := map[string][]byte{}
	for _, profile := range manifest.Profiles {
		if profile.Version == "" || len(profile.Roots) == 0 {
			return nil, fmt.Errorf("Android trust profile is empty")
		}
		p := Profile{Version: profile.Version}
		for _, fp := range profile.Roots {
			cert, ok := cache[fp]
			if !ok {
				raw, err := embeddedData.ReadFile("data/roots/" + fp + ".pem")
				if err != nil {
					return nil, fmt.Errorf("Android trust root is unavailable")
				}
				block, rest := pem.Decode(raw)
				if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
					return nil, fmt.Errorf("Android trust root PEM is invalid")
				}
				digest := sha256.Sum256(block.Bytes)
				if hex.EncodeToString(digest[:]) != fp {
					return nil, fmt.Errorf("Android trust root fingerprint is invalid")
				}
				// Some authentic historical anchors have encodings rejected by
				// modern Go (for example negative serial numbers). Preserve the
				// pinned DER without global parser overrides or modifying it.
				// A failed path in an affected profile must remain unknown.
				cert, _ = x509.ParseCertificate(block.Bytes)
				if cert == nil {
					unsupportedSubjects[fp] = extractSubjectDER(block.Bytes)
				}
				cache[fp] = cert
			}
			if cert == nil {
				p.UnsupportedRoots++
				if subject := unsupportedSubjects[fp]; len(subject) > 0 {
					p.UnsupportedRootSubjects = append(p.UnsupportedRootSubjects, subject)
				}
				continue
			}
			p.Roots = append(p.Roots, cert)
		}
		profiles = append(profiles, p)
	}
	return NewAnalyzer(manifest.Version, profiles), nil
}

// extractSubjectDER reads ASN.1 containers as raw values, including the serial
// INTEGER. This preserves historical negative serials without relaxing the
// certificate parser or changing any certificate bytes.
func extractSubjectDER(der []byte) []byte {
	var outer, tbs asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return nil
	}
	_, err = asn1.Unmarshal(outer.Bytes, &tbs)
	if err != nil || tbs.Class != asn1.ClassUniversal || tbs.Tag != asn1.TagSequence {
		return nil
	}
	rest = tbs.Bytes
	var field asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &field)
	if err != nil {
		return nil
	}
	if field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil
		}
	}
	if field.Class != asn1.ClassUniversal || field.Tag != asn1.TagInteger {
		return nil
	}
	// After serial: signature, issuer, validity, then subject.
	for i := 0; i < 4; i++ {
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil || field.Class != asn1.ClassUniversal || field.Tag != asn1.TagSequence {
			return nil
		}
	}
	return append([]byte{}, field.FullBytes...)
}
