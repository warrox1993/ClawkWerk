package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/scan"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

func TestReadiness(t *testing.T) {
	cases := []struct {
		name   string
		hasCmd bool
		err    error
		raw    assess.RawEvidence
		want   Readiness
	}{
		{"os non supporté", false, nil, assess.RawEvidence{}, ReadyUnsupported},
		{"injoignable (transport)", true, errors.New("dial timeout"), assess.RawEvidence{}, ReadyUnreachable},
		{"droits refusés (sortie)", true, nil, assess.RawEvidence{Data: []byte("Access is denied.")}, ReadyPrivilege},
		{"droits refusés (erreur)", true, nil, assess.RawEvidence{CollectErr: "cat: Permission denied"}, ReadyPrivilege},
		{"preuve absente => injoignable", true, nil, assess.RawEvidence{CollectErr: "preuve absente (x)"}, ReadyUnreachable},
		{"lisible", true, nil, assess.RawEvidence{Data: []byte(`{"ok":true}`)}, ReadyOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, _ := readiness(c.hasCmd, c.err, c.raw); got != c.want {
				t.Errorf("readiness = %q, attendu %q", got, c.want)
			}
		})
	}
}

func TestHostsNeedingProvisioning(t *testing.T) {
	rows := []PreflightRow{
		{Host: "B", Status: ReadyPrivilege},
		{Host: "A", Status: ReadyPrivilege},
		{Host: "A", Status: ReadyPrivilege}, // doublon
		{Host: "C", Status: ReadyOK},        // pas un manque de droits
	}
	got := HostsNeedingProvisioning(rows)
	if len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Errorf("dédoublonnage/tri inattendu : %v", got)
	}
}

func TestEngine_Preflight_ClassifiesAccess(t *testing.T) {
	dir := t.TempDir()
	// Preuve lisible pour PC1 ; accès refusé (marqueur Windows) pour WIN7.
	mustWrite(t, filepath.Join(dir, "PC1.DE.CM-01.2.json"), `{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":1}`)
	mustWrite(t, filepath.Join(dir, "WIN7.DE.CM-01.2.json"), "Access is denied.")
	e := &Engine{
		Source:   scan.NewFileSource(dir),
		Journal:  audit.NewMemoryJournal(),
		Controls: DefaultControls(),
	}
	sc := scope.AuditScope{Hosts: []scope.ScopedHost{
		{Ref: assess.HostRef{ID: "PC1", OS: "windows"}},
		{Ref: assess.HostRef{ID: "WIN7", OS: "windows"}},
		{Ref: assess.HostRef{ID: "MAC", OS: "macos"}},
	}}
	rows := e.Preflight(context.Background(), sc)

	if got := rowStatus(rows, "PC1", "DE.CM-01.2"); got != ReadyOK {
		t.Errorf("PC1 doit être lisible, obtenu %q", got)
	}
	if got := rowStatus(rows, "WIN7", "DE.CM-01.2"); got != ReadyPrivilege {
		t.Errorf("WIN7 doit être « droits insuffisants », obtenu %q", got)
	}
	if got := rowStatus(rows, "MAC", "DE.CM-01.2"); got != ReadyUnsupported {
		t.Errorf("MAC doit être « OS non supporté », obtenu %q", got)
	}
	// Le preflight ne couvre QUE les contrôles scannables (pas les déclaratifs).
	for _, r := range rows {
		if r.ControlID == "GV.PO-01.1" {
			t.Error("le preflight ne doit pas inclure un contrôle déclaratif")
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rowStatus(rows []PreflightRow, host, ctrl string) Readiness {
	for _, r := range rows {
		if r.Host == host && r.ControlID == ctrl {
			return r.Status
		}
	}
	return ""
}

// Régression : le preflight annonçait « Périmètre de droits suffisant » dès
// qu'aucun hôte ne manquait de droits, même quand TOUTES les collectes avaient
// échoué (hôtes injoignables, preuves absentes).
func TestSummarizePreflight(t *testing.T) {
	cases := []struct {
		name       string
		rows       []PreflightRow
		sufficient bool
		verdict    string
	}{
		{"aucune ligne", nil, false, "rien n'a pu être vérifié"},
		{"que des OS non supportés", []PreflightRow{{Host: "MAC", Status: ReadyUnsupported}}, false, "rien n'a pu être vérifié"},
		{"tout injoignable", []PreflightRow{
			{Host: "A", Status: ReadyUnreachable}, {Host: "B", Status: ReadyUnreachable},
			{Host: "FW", Status: ReadyUnsupported},
		}, false, "NON vérifié"},
		{"tout illisible", []PreflightRow{{Host: "A", Status: ReadyUnreadable}}, false, "NON vérifié"},
		{"partiel", []PreflightRow{
			{Host: "A", Status: ReadyOK}, {Host: "B", Status: ReadyUnreachable},
		}, false, "1 collectes lisibles sur 2"},
		{"droits manquants", []PreflightRow{
			{Host: "A", Status: ReadyOK}, {Host: "B", Status: ReadyPrivilege},
		}, false, "incomplet"},
		{"tout lisible (OS non supporté ignoré)", []PreflightRow{
			{Host: "A", Status: ReadyOK}, {Host: "B", Status: ReadyOK},
			{Host: "FW", Status: ReadyUnsupported},
		}, true, "suffisant : 2 collectes lisibles sur 2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := SummarizePreflight(c.rows)
			if s.Sufficient != c.sufficient {
				t.Errorf("Sufficient = %v, attendu %v (%s)", s.Sufficient, c.sufficient, s.Verdict)
			}
			if !strings.Contains(s.Verdict, c.verdict) {
				t.Errorf("verdict %q ne contient pas %q", s.Verdict, c.verdict)
			}
		})
	}
	s := SummarizePreflight([]PreflightRow{
		{Host: "B", Status: ReadyUnreachable}, {Host: "A", Status: ReadyUnreachable},
		{Host: "C", Status: ReadyUnreadable}, {Host: "D", Status: ReadyPrivilege},
	})
	if strings.Join(s.UnreachableHosts, ",") != "A,B" || strings.Join(s.UnreadableHosts, ",") != "C" ||
		strings.Join(s.ProvisionHosts, ",") != "D" {
		t.Errorf("listes d'hôtes inattendues : %+v", s)
	}
}

// Une collecte qui aboutit mais dont la sortie est rejetée par le normaliseur
// n'est pas « lisible » : le preflight la signale comme preuve illisible, ou
// comme manque de droits si la sonde l'indique elle-même.
func TestEngine_Preflight_RunsNormalizer(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "L1.DE.CM-01.1.json"), "sortie sans rapport\n")
	e := &Engine{
		Source:   scan.NewFileSource(dir),
		Journal:  audit.NewMemoryJournal(),
		Controls: DefaultControls(),
	}
	sc := scope.AuditScope{Hosts: []scope.ScopedHost{{Ref: assess.HostRef{ID: "L1", OS: "linux"}}}}
	rows := e.Preflight(context.Background(), sc)
	if got := rowStatus(rows, "L1", "DE.CM-01.1"); got != ReadyUnreadable {
		t.Errorf("sortie non interprétable : attendu %q, obtenu %q", ReadyUnreadable, got)
	}
	if st, _ := normalizeReadiness(errors.New("droits insuffisants : état du pare-feu illisible")); st != ReadyPrivilege {
		t.Errorf("un rejet « droits insuffisants » doit donner %q, obtenu %q", ReadyPrivilege, st)
	}
}
