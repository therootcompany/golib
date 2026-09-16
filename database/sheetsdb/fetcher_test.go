package sheetsdb

import "testing"

func TestConfigSourceURLIdentitiesPrimary(t *testing.T) {
	config := Config{Rows: []ConfigRow{{Key: "identities", Value: "identities.tsv"}}}

	value, found, duplicate := config.SourceURL("identities")
	if !found || duplicate || value != "identities.tsv" {
		t.Fatalf("SourceURL(identities) = %q, %v, %v; want identities.tsv, true, false", value, found, duplicate)
	}
}

func TestConfigSourceURLProfilesAlias(t *testing.T) {
	config := Config{Rows: []ConfigRow{{Key: "identities", Value: "identities.tsv"}}}

	value, found, duplicate := config.SourceURL("profiles")
	if !found || duplicate || value != "identities.tsv" {
		t.Fatalf("SourceURL(profiles) = %q, %v, %v; want identities.tsv, true, false", value, found, duplicate)
	}
}
