package scope

import (
	"encoding/json"
	"strings"
	"testing"
)

// Le secret d'un credential ne doit JAMAIS apparaître dans le JSON.
func TestCredential_SecretNeverSerialized(t *testing.T) {
	c := NewCredential("svc-audit-ro", "auditor", []byte("Sup3rS3cret!"))
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "Sup3rS3cret") {
		t.Fatalf("le secret a fuité dans le JSON : %s", b)
	}
	// mais la référence et le username, eux, sont bien présents (traçabilité)
	if !strings.Contains(string(b), "svc-audit-ro") || !strings.Contains(string(b), "auditor") {
		t.Errorf("ref/username absents du JSON : %s", b)
	}
}

func TestCredential_ZeroErasesSecret(t *testing.T) {
	raw := []byte("secret")
	c := NewCredential("r", "u", raw)
	if string(c.Secret()) != "secret" {
		t.Fatalf("secret non conservé")
	}
	c.Zero()
	if c.Secret() != nil {
		t.Errorf("secret non effacé après Zero()")
	}
}

// NewCredential copie le secret : effacer la source ne doit pas altérer le
// credential.
func TestCredential_CopiesSecret(t *testing.T) {
	raw := []byte("abc")
	c := NewCredential("r", "u", raw)
	for i := range raw {
		raw[i] = 'X'
	}
	if string(c.Secret()) != "abc" {
		t.Errorf("le credential partage la mémoire de l'appelant : %q", c.Secret())
	}
}
