package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var loadTime = time.Date(2026, 9, 28, 14, 30, 5, 0, time.UTC)

const validScope = `{
  "client": "ACME SPRL",
  "provided_by": "DSI client",
  "hosts": [
    {"id": "ACME-PC01", "os": "Windows", "role": "workstation", "address": "acme-pc01.acme.lan", "transport": "WinRM", "port": 5986, "cred_ref": "svc-audit-ro"},
    {"id": "ACME-LNX01", "os": "linux", "address": "10.0.0.20", "transport": "ssh", "cred_ref": "svc-linux-ro"},
    {"id": "ACME-FW01", "os": "routeros", "role": "firewall", "address": "acme-fw01.acme.lan", "transport": "ssh", "port": 22, "cred_ref": "svc-audit-ro"}
  ]
}`

func TestParse_ValidScope(t *testing.T) {
	sc, err := Parse([]byte(validScope), loadTime)
	if err != nil {
		t.Fatalf("périmètre valide refusé : %v", err)
	}
	if sc.ClientRef != "ACME SPRL" || sc.ProvidedBy != "DSI client" {
		t.Errorf("client/fournisseur inattendus : %q / %q", sc.ClientRef, sc.ProvidedBy)
	}
	if !sc.ProvidedAt.Equal(loadTime) {
		t.Errorf("ProvidedAt = %v, attendu l'heure de chargement %v", sc.ProvidedAt, loadTime)
	}
	if len(sc.Hosts) != 3 {
		t.Fatalf("3 machines attendues, obtenu %d", len(sc.Hosts))
	}
	pc := sc.Hosts[0]
	// OS et transport sont normalisés en minuscules (clés du registre).
	if pc.Ref.OS != "windows" || pc.Transport != WinRM || pc.Port != 5986 || pc.Ref.Role != "workstation" {
		t.Errorf("machine 1 mal décodée : %+v", pc)
	}
	if sc.Hosts[1].Port != 0 || sc.Hosts[1].Transport != SSH {
		t.Errorf("machine 2 : port par défaut (0) et ssh attendus : %+v", sc.Hosts[1])
	}
	if got := sc.CredRefs(); strings.Join(got, ",") != "svc-audit-ro,svc-linux-ro" {
		t.Errorf("CredRefs = %v", got)
	}
}

func TestParse_ProvidedAtFromFile(t *testing.T) {
	data := `{"client":"X","provided_at":"2026-09-01T09:00:00Z","hosts":[{"id":"H1","os":"linux","address":"h1","transport":"ssh","cred_ref":"c"}]}`
	sc, err := Parse([]byte(data), loadTime)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC); !sc.ProvidedAt.Equal(want) {
		t.Errorf("ProvidedAt = %v, attendu %v", sc.ProvidedAt, want)
	}
}

func TestParse_Rejects(t *testing.T) {
	host := func(fields string) string {
		return `{"client":"ACME","hosts":[{` + fields + `}]}`
	}
	cases := []struct {
		name, data, want string
	}{
		{"JSON cassé", `{"client":`, "JSON invalide"},
		{"champ inconnu", `{"client":"A","clients":"B","hosts":[]}`, "JSON invalide"},
		{"client absent", `{"hosts":[{"id":"H","os":"linux","address":"h","transport":"ssh","cred_ref":"c"}]}`, "client"},
		{"aucune machine", `{"client":"ACME","hosts":[]}`, "au moins une machine"},
		{"id absent", host(`"os":"linux","address":"h","transport":"ssh","cred_ref":"c"`), "id"},
		{"id avec chemin", host(`"id":"../etc","os":"linux","address":"h","transport":"ssh","cred_ref":"c"`), "séparateur"},
		{"os absent", host(`"id":"H","address":"h","transport":"ssh","cred_ref":"c"`), "os"},
		{"adresse absente", host(`"id":"H","os":"linux","transport":"ssh","cred_ref":"c"`), "address"},
		{"plage CIDR", host(`"id":"H","os":"linux","address":"10.0.0.0/24","transport":"ssh","cred_ref":"c"`), "plage"},
		{"motif", host(`"id":"H","os":"linux","address":"*.acme.lan","transport":"ssh","cred_ref":"c"`), "plage"},
		{"transport inconnu", host(`"id":"H","os":"linux","address":"h","transport":"telnet","cred_ref":"c"`), "transport"},
		{"port hors plage", host(`"id":"H","os":"linux","address":"h","transport":"ssh","port":70000,"cred_ref":"c"`), "port"},
		{"credential absent", host(`"id":"H","os":"linux","address":"h","transport":"ssh"`), "cred_ref"},
		{"doublon", `{"client":"A","hosts":[{"id":"H","os":"linux","address":"a","transport":"ssh","cred_ref":"c"},{"id":"H","os":"linux","address":"b","transport":"ssh","cred_ref":"c"}]}`, "double"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.data), loadTime)
			if err == nil {
				t.Fatalf("périmètre invalide accepté")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("erreur %q ne mentionne pas %q", err, c.want)
			}
		})
	}
}

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(path, []byte(validScope), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := LoadFile(path, loadTime)
	if err != nil || len(sc.Hosts) != 3 {
		t.Fatalf("LoadFile : %v (%d machines)", err, len(sc.Hosts))
	}
	if _, err := LoadFile(filepath.Join(t.TempDir(), "absent.json"), loadTime); err == nil {
		t.Error("un fichier absent doit être une erreur")
	}
}

// L'exemple livré dans sample/ doit rester valide.
func TestSampleScopeIsValid(t *testing.T) {
	sc, err := LoadFile(filepath.Join("..", "..", "sample", "scope.json"), loadTime)
	if err != nil {
		t.Fatalf("sample/scope.json invalide : %v", err)
	}
	if len(sc.Hosts) == 0 {
		t.Fatal("sample/scope.json ne contient aucune machine")
	}
}

func TestSessionID(t *testing.T) {
	cases := map[string]string{
		"ACME SPRL":                "acme-sprl-20260928-143005",
		"  Société Générale ":      "societe-generale-20260928-143005",
		"Brüssel & Liège (siège)":  "brussel-liege-siege-20260928-143005",
		"---":                      "audit-20260928-143005",
		"Aéroport de Liège / NIS2": "aeroport-de-liege-nis2-20260928-143005",
	}
	for client, want := range cases {
		if got := SessionID(client, loadTime); got != want {
			t.Errorf("SessionID(%q) = %q, attendu %q", client, got, want)
		}
	}
	// Deux audits à une seconde d'écart n'ont jamais le même identifiant.
	if SessionID("ACME", loadTime) == SessionID("ACME", loadTime.Add(time.Second)) {
		t.Error("identifiants de session identiques pour deux horodatages différents")
	}
}
