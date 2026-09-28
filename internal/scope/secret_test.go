package scope

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
)

// TestScope_SecretAbsentFromScopeJSON : un périmètre complet (hôtes + réfs de
// credentials) sérialisé ne contient jamais de secret — les hôtes ne portent
// qu'une CredRef logique, jamais le secret (complète les tests Credential_*).
func TestScope_SecretAbsentFromScopeJSON(t *testing.T) {
	const canary = "TOP-SECRET-CANARY-9f3a2b"
	sc := AuditScope{
		ClientRef: "ACME",
		Hosts: []ScopedHost{
			{Ref: assess.HostRef{ID: "SRV01", OS: "linux"}, Address: "srv01.lan", Transport: SSH, CredRef: "svc-audit-ro"},
		},
	}
	b, _ := json.Marshal(sc)
	if strings.Contains(string(b), canary) {
		t.Fatal("un secret ne doit jamais transiter par le périmètre sérialisé")
	}
	if !strings.Contains(string(b), "svc-audit-ro") {
		t.Error("la référence logique du credential doit apparaître (traçabilité)")
	}
}
