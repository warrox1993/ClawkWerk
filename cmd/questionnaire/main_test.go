package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/engine"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

func TestNormalizeLevel(t *testing.T) {
	for in, want := range map[string]string{"basic": cyfun.LevelBasic, "Important": cyfun.LevelImportant, "ESSENTIAL": cyfun.LevelEssential} {
		if got, err := normalizeLevel(in); err != nil || got != want {
			t.Errorf("normalizeLevel(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := normalizeLevel("expert"); err == nil {
		t.Error("niveau inconnu accepté")
	}
}

// -level change réellement le catalogue : chaque niveau est un sur-ensemble
// strict du précédent.
func TestLevelsAreNestedCatalogues(t *testing.T) {
	n := func(lvl string) int { return len(engine.AllQuestions(engine.ControlsForLevel(lvl))) }
	b, i, e := n(cyfun.LevelBasic), n(cyfun.LevelImportant), n(cyfun.LevelEssential)
	if !(b > 0 && b < i && i < e) {
		t.Errorf("catalogues non imbriqués : basic=%d important=%d essential=%d", b, i, e)
	}
}

func TestWriteResponses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	if err := writeResponses(path, survey.Responses{"A/documentation/x": "defined"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("fichier absent ou permissions %v (0600 attendu)", st.Mode().Perm())
	}
	var got map[string]string
	b, _ := os.ReadFile(path)
	if json.Unmarshal(b, &got) != nil || got["A/documentation/x"] != "defined" {
		t.Errorf("contenu inattendu : %s", b)
	}
}
