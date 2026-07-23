package engine

import (
	"context"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/audit"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/scan"
	"projetcyber/internal/scope"
)

// DÉGRADATION GRACIEUSE : un contrôle scannable dont le scan échoue sur TOUS les
// hôtes (ici un OS non supporté) bascule son Implementation sur l'attestation du
// questionnaire de repli — jamais un 0 imposé. Le score PROPOSÉ par le scan
// (NotAssessed) reste tracé, et la bascule est marquée.
func TestEngine_Run_ScanGapFallsBackToAttestation(t *testing.T) {
	sc := scope.AuditScope{Hosts: []scope.ScopedHost{
		{Ref: assess.HostRef{ID: "MAC-01", OS: "macos"}, CredRef: "svc"},
	}}
	e := &Engine{
		Source:     scan.NewFileSource(t.TempDir()),
		Journal:    audit.NewMemoryJournal(),
		Controls:   DefaultControls(),
		DocScores:  map[string]cyfun.MaturityLevel{"DE.CM-01.2": cyfun.Defined},
		ImplScores: map[string]cyfun.MaturityLevel{"DE.CM-01.2": cyfun.Defined}, // attestation de repli
	}
	results, err := e.Run(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	r := resultByID(t, results, "DE.CM-01.2")
	if r.ProposedImpl != cyfun.NotAssessed {
		t.Errorf("le scan doit proposer NotAssessed (macOS non supporté), obtenu %d", r.ProposedImpl)
	}
	if !r.ImplFromAttestation {
		t.Error("la bascule sur attestation doit être marquée (ImplFromAttestation)")
	}
	if r.FinalImpl != cyfun.Defined {
		t.Errorf("FinalImpl doit basculer sur l'attestation (3), obtenu %d", r.FinalImpl)
	}
	if !r.Assessed() {
		t.Error("avec Doc + attestation Impl, le contrôle doit être considéré évalué")
	}
}

// Même trou mais SANS attestation : FinalImpl reste NotAssessed (jamais forcé à
// un 0 « faille »), la bascule n'est pas marquée, et le contrôle n'est pas
// considéré évalué (il sera signalé « à évaluer » par la session).
func TestEngine_Run_ScanGapWithoutAttestationStaysUnassessed(t *testing.T) {
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
	r := resultByID(t, results, "DE.CM-01.2")
	if r.FinalImpl != cyfun.NotAssessed {
		t.Errorf("sans attestation, FinalImpl doit rester NotAssessed, obtenu %d", r.FinalImpl)
	}
	if r.ImplFromAttestation {
		t.Error("aucune attestation : ImplFromAttestation doit être faux")
	}
	if r.Assessed() {
		t.Error("sans scan ni attestation, le contrôle ne doit pas être considéré évalué")
	}
}
