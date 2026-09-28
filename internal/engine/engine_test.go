package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/scan"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

// writeEvidence dépose une preuve antivirus pour un hôte donné.
func writeEvidence(t *testing.T, dir, hostID, json string) {
	t.Helper()
	p := filepath.Join(dir, hostID+".DE.CM-01.2.json")
	if err := os.WriteFile(p, []byte(json), 0o600); err != nil {
		t.Fatal(err)
	}
}

// resultByID retrouve un contrôle par son ID dans les résultats (le registre
// contient désormais plusieurs contrôles ; on ne se repose plus sur l'ordre).
func resultByID(t *testing.T, results []assess.ControlResult, id string) assess.ControlResult {
	t.Helper()
	for _, r := range results {
		if r.Meta.ID == id {
			return r
		}
	}
	t.Fatalf("contrôle %s absent des résultats", id)
	return assess.ControlResult{}
}

func TestEngine_Run_WorstCaseAcrossHosts(t *testing.T) {
	dir := t.TempDir()
	// Format BRUT Defender (normalisé par le moteur avant évaluation).
	// PC-OK : antivirus actif, temps réel, définitions fraîches -> Managed (4)
	writeEvidence(t, dir, "PC-OK", `{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":2}`)
	// PC-KO : antivirus désactivé -> Initial (1)
	writeEvidence(t, dir, "PC-KO", `{"AntivirusEnabled":false,"RealTimeProtectionEnabled":false,"AntivirusSignatureAge":0}`)

	sc := scope.AuditScope{
		ClientRef: "ACME",
		Hosts: []scope.ScopedHost{
			{Ref: assess.HostRef{ID: "PC-OK", OS: "windows"}, Transport: scope.WinRM, CredRef: "svc"},
			{Ref: assess.HostRef{ID: "PC-KO", OS: "windows"}, Transport: scope.WinRM, CredRef: "svc"},
		},
	}

	e := &Engine{
		Source:   scan.NewFileSource(dir),
		Journal:  audit.NewMemoryJournal(),
		Creds:    map[string]*scope.Credential{"svc": scope.NewCredential("svc", "auditor", []byte("x"))},
		Controls: DefaultControls(),
		DocScores: map[string]cyfun.MaturityLevel{
			"DE.CM-01.2": cyfun.Defined, // le questionnaire a donné Doc=3
		},
	}

	results, err := e.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != len(DefaultControls()) {
		t.Fatalf("attendu %d ControlResult, obtenu %d", len(DefaultControls()), len(results))
	}
	r := resultByID(t, results, "DE.CM-01.2")

	// Agrégat = pire cas -> Initial (1), à cause de PC-KO.
	if r.ProposedImpl != cyfun.Initial {
		t.Errorf("ProposedImpl = %d, attendu Initial (1)", r.ProposedImpl)
	}
	if r.FinalImpl != cyfun.Initial {
		t.Errorf("FinalImpl = %d, attendu Initial (1)", r.FinalImpl)
	}
	// Documentation vient du questionnaire injecté.
	if r.FinalDoc != cyfun.Defined {
		t.Errorf("FinalDoc = %d, attendu Defined (3)", r.FinalDoc)
	}
	// Maturité = moyenne(3,1) = 2,0 -> Key Measure NON conforme.
	if r.Maturity() != 2.0 {
		t.Errorf("Maturity = %v, attendu 2.0", r.Maturity())
	}
	if r.ConformBasic() {
		t.Error("DE.CM-01.2 à 2,0 ne doit PAS être conforme")
	}
	if len(r.HostAssessments) != 2 {
		t.Errorf("attendu 2 évaluations d'hôtes, obtenu %d", len(r.HostAssessments))
	}
}

func TestEngine_Run_UnsupportedOSIsNotApplicable(t *testing.T) {
	sc := scope.AuditScope{Hosts: []scope.ScopedHost{
		{Ref: assess.HostRef{ID: "MAC-01", OS: "macos"}, CredRef: "svc"},
	}}
	e := &Engine{
		Source:   scan.NewFileSource(t.TempDir()),
		Journal:  audit.NewMemoryJournal(),
		Controls: DefaultControls(),
	}
	results, err := e.Run(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	ha := results[0].HostAssessments[0]
	if ha.Findings[0].Status != assess.StatusNA {
		t.Errorf("OS non supporté doit être N/A, obtenu %q", ha.Findings[0].Status)
	}
}

// Un contrôle déclaratif (Evaluator nil) ne contacte aucun hôte : ses deux
// axes viennent du questionnaire, et il ne produit pas d'évaluation par hôte.
func TestEngine_Run_DeclarativeControlFromQuestionnaire(t *testing.T) {
	e := &Engine{
		Source:   scan.NewFileSource(t.TempDir()),
		Journal:  audit.NewMemoryJournal(),
		Controls: DefaultControls(),
		DocScores: map[string]cyfun.MaturityLevel{
			"GV.PO-01.1": cyfun.Defined, // questionnaire : Doc=3
		},
		ImplScores: map[string]cyfun.MaturityLevel{
			"GV.PO-01.1": cyfun.Managed, // questionnaire : Impl=4
		},
	}
	// Aucun hôte : un contrôle scannable serait NotAssessed, mais le déclaratif
	// doit quand même être scoré depuis le questionnaire.
	results, err := e.Run(context.Background(), scope.AuditScope{})
	if err != nil {
		t.Fatal(err)
	}
	r := resultByID(t, results, "GV.PO-01.1")
	if len(r.HostAssessments) != 0 {
		t.Errorf("un contrôle déclaratif ne doit produire aucune évaluation d'hôte, obtenu %d", len(r.HostAssessments))
	}
	if r.FinalDoc != cyfun.Defined || r.FinalImpl != cyfun.Managed {
		t.Errorf("axes questionnaire: Doc=%d Impl=%d, attendu 3 et 4", r.FinalDoc, r.FinalImpl)
	}
	if r.Maturity() != 3.5 {
		t.Errorf("Maturity = %v, attendu 3.5", r.Maturity())
	}
}

// L'override consultant remplace l'Implementation FINALE tout en conservant la
// valeur PROPOSÉE (traçabilité) — c'est le chemin honnête vers un 5/5.
func TestEngine_Run_AppliesOverride(t *testing.T) {
	dir := t.TempDir()
	writeEvidence(t, dir, "PC-01", `{"AntivirusEnabled":false,"RealTimeProtectionEnabled":false,"AntivirusSignatureAge":0}`) // scan -> Initial (1)
	e := &Engine{
		Source:    scan.NewFileSource(dir),
		Journal:   audit.NewMemoryJournal(),
		Controls:  DefaultControls(),
		Creds:     map[string]*scope.Credential{"svc": scope.NewCredential("svc", "u", []byte("x"))},
		DocScores: map[string]cyfun.MaturityLevel{"DE.CM-01.2": cyfun.Optimizing},
		Overrides: map[string]Override{
			"DE.CM-01.2": {Impl: cyfun.Optimizing, Reason: "amélioration continue démontrée, métriques < 0,5% (preuve dossier §4)"},
		},
	}
	sc := scope.AuditScope{Hosts: []scope.ScopedHost{
		{Ref: assess.HostRef{ID: "PC-01", OS: "windows"}, Transport: scope.WinRM, CredRef: "svc"},
	}}
	results, err := e.Run(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	r := resultByID(t, results, "DE.CM-01.2")
	if r.ProposedImpl != cyfun.Initial {
		t.Errorf("ProposedImpl (scan) doit rester Initial(1), obtenu %d", r.ProposedImpl)
	}
	if r.FinalImpl != cyfun.Optimizing || !r.ImplOverridden || r.OverrideReason == "" {
		t.Errorf("override mal appliqué: final=%d overridden=%v reason=%q", r.FinalImpl, r.ImplOverridden, r.OverrideReason)
	}
	if r.Maturity() != 5.0 { // moyenne(5,5)
		t.Errorf("maturité après override attendue 5.0, obtenu %v", r.Maturity())
	}
}

// Un run complet doit journaliser les accès (preuve d'audit).
func TestEngine_Run_PopulatesJournal(t *testing.T) {
	dir := t.TempDir()
	writeEvidence(t, dir, "PC-01", `{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":1}`)
	j := audit.NewMemoryJournal()
	e := &Engine{
		Source:   scan.NewFileSource(dir),
		Journal:  j,
		Controls: DefaultControls(),
		Creds:    map[string]*scope.Credential{"svc": scope.NewCredential("svc", "auditor", []byte("x"))},
	}
	sc := scope.AuditScope{Hosts: []scope.ScopedHost{
		{Ref: assess.HostRef{ID: "PC-01", OS: "windows"}, Transport: scope.WinRM, CredRef: "svc"},
	}}
	if _, err := e.Run(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	if len(j.Entries()) == 0 {
		t.Error("le journal doit contenir les accès effectués")
	}
}
