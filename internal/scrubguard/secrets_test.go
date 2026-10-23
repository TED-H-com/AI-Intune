package scrubguard

import (
	"strings"
	"testing"
)

func TestScrubCredentials(t *testing.T) {
	fixtures := []struct {
		name  string
		input string
		flag  string
	}{
		{"token equals", "token=fixture-value", FlagAssignment},
		{"api key spaces", "API_KEY = fixture-value", FlagAssignment},
		{"quoted password", "password: 'two words'", FlagAssignment},
		{"json client secret", `{"client_secret":"fixture-value"}`, FlagAssignment},
		{"service token", "service_token=fixture-value&other=value", FlagAssignment},
		{"authorization bearer", "Authorization: Bearer fixture-value", FlagAuthorization},
		{"authorization basic", "authorization=Basic Zml4dHVyZTpwYXNz", FlagAuthorization},
		{"bare bearer", "Bearer fixture-value", FlagAuthorization},
		{"openai", "sk-proj-fixtureCredential", FlagProviderToken},
		{"github", "ghp_fixtureCredential", FlagProviderToken},
		{"github fine grained", "github_pat_fixtureCredential", FlagProviderToken},
		{"gitlab", "glpat-fixtureCredential", FlagProviderToken},
		{"slack", "xoxb-fixtureCredential", FlagProviderToken},
		{"google", "AIzaFixtureCredential", FlagProviderToken},
		{"aws", "AKIAFIXTURECREDENTIAL", FlagProviderToken},
		{"stripe", "sk_live_fixtureCredential", FlagProviderToken},
		{"npm", "npm_fixtureCredential", FlagProviderToken},
		{"hugging face", "hf_fixtureCredential", FlagProviderToken},
		{"url userinfo", "https://user:fixture-value@example.invalid/path", FlagURLCredentials},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.fixtureSignature", FlagJWT},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----\nfixture material\n-----END RSA PRIVATE KEY-----", FlagPEM},
		{"truncated pem", "-----BEGIN PRIVATE KEY-----\ntruncated", FlagPEM},
		{"entropy", "aB3dE6gH9jK2mN5pQ8sT1vW4", FlagEntropy},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			result := ScrubWithResult(fixture.input)
			if result.Count < 1 || !strings.Contains(result.Value, RedactionMarker) || result.Value == fixture.input {
				t.Fatal("credential fixture was not redacted")
			}
			if !contains(result.Flags, fixture.flag) {
				t.Fatalf("flags=%v, want %s", result.Flags, fixture.flag)
			}
			again := ScrubWithResult(result.Value)
			if again.Value != result.Value || again.Count != 0 || len(again.Flags) != 0 {
				t.Fatal("scrub is not idempotent")
			}
		})
	}
}

func TestScrubOrdinaryText(t *testing.T) {
	for _, input := range []string{
		"Machine healthy", "/var/log/app.log", "/srv/example/releases/current/config.json",
		"linux amd64", "v1.2.3", "service restarted successfully", "", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"monkey=value", "hockey=enabled", "tokenizer=ready", "123e4567-e89b-12d3-a456-426614174000",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		if got, n := Scrub(input); got != input || n != 0 {
			t.Fatalf("ordinary fixture changed: %q => %q", input, got)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
