package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/engine"
	"github.com/warrox1993/clawkwerk/internal/scan"
	"github.com/warrox1993/clawkwerk/internal/scope"
	"github.com/warrox1993/clawkwerk/internal/session"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

var sampleDir = filepath.Join("..", "..", "sample")

// runDemo rejoue l'audit de démonstration (périmètre, preuves et questionnaire
// livrés dans sample/) au niveau demandé, exactement comme la CLI par défaut.
func runDemo(t *testing.T, level string) session.AuditSession {
	t.Helper()
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	sc, err := loadScope(filepath.Join(sampleDir, "scope.json"), now)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := resolveCreds("file", "", sc)
	if err != nil {
		t.Fatal(err)
	}
	responses, err := loadResponses(filepath.Join(sampleDir, "responses.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctrls := engine.ControlsForLevel(level)
	q := survey.New(engine.AllQuestions(ctrls), nil)
	if missing := q.Unanswered(responses); len(missing) > 0 {
		t.Errorf("niveau %s : %d question(s) sans réponse dans sample/responses.json : %v", level, len(missing), missing)
	}
	eng := &engine.Engine{
		Source:     scan.NewFileSource(filepath.Join(sampleDir, "evidence")),
		Journal:    audit.NewMemoryJournal(),
		Creds:      creds,
		Controls:   ctrls,
		DocScores:  q.ScoreMap(survey.Documentation, responses),
		ImplScores: q.ScoreMap(survey.Implementation, responses),
	}
	results, err := eng.Run(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	return session.NewAtLevel(scope.SessionID(sc.ClientRef, now), level, sc, results, eng.Journal.Entries(), now, now)
}

// La démo doit produire un verdict COMPLET (jamais « audit incomplet ») aux
// trois niveaux, avec un questionnaire entièrement rempli.
func TestDemo_CompleteVerdictAtEveryLevel(t *testing.T) {
	for _, level := range []string{cyfun.LevelBasic, cyfun.LevelImportant, cyfun.LevelEssential} {
		sess := runDemo(t, level)
		if sess.Conformity.Incomplete {
			t.Errorf("niveau %s : audit incomplet, contrôles non évalués : %v", level, sess.Conformity.UnassessedControls)
		}
		if err := audit.Verify(sess.Journal); err != nil {
			t.Errorf("niveau %s : chaîne du journal rompue : %v", level, err)
		}
	}
}

// Les 16 contrôles scannables du niveau Basic doivent tous être MESURÉS par le
// scan sur au moins une machine de la démo, et non repris de l'attestation.
func TestDemo_AllBasicScannableControlsMeasured(t *testing.T) {
	sess := runDemo(t, cyfun.LevelBasic)
	scannable := 0
	for _, c := range engine.ControlsForLevel(cyfun.LevelBasic) {
		if len(c.Commands) > 0 {
			scannable++
		}
	}
	if scannable != 16 {
		t.Fatalf("%d contrôles scannables au niveau Basic, 16 attendus", scannable)
	}
	measured := 0
	for _, r := range sess.Results {
		if len(r.HostAssessments) == 0 {
			continue // contrôle déclaratif
		}
		if r.ProposedImpl == cyfun.NotAssessed || r.ImplFromAttestation {
			t.Errorf("%s : non mesuré par le scan dans la démo", r.Meta.ID)
			continue
		}
		measured++
	}
	if measured != 16 {
		t.Errorf("%d contrôles scannables mesurés, 16 attendus", measured)
	}
}
