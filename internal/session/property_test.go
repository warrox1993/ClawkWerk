package session

import (
	"math/rand"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// res fabrique un ControlResult minimal (Doc/Impl finaux, Key Measure).
func res(id string, km bool, doc, impl cyfun.MaturityLevel) assess.ControlResult {
	return assess.ControlResult{
		Meta:      cyfun.ControlMeta{ID: id, KeyMeasure: km, Level: cyfun.LevelBasic},
		FinalDoc:  doc,
		FinalImpl: impl,
	}
}

// resCat comme res, avec une catégorie explicite (pour le seuil par catégorie).
func resCat(id, cat string, km bool, doc, impl cyfun.MaturityLevel) assess.ControlResult {
	r := res(id, km, doc, impl)
	r.Meta.Category = cat
	return r
}

// TestEssential_CategoryThreshold : à Essential, une catégorie sous 3/5 rend
// l'audit non conforme — même si aucun Key Measure n'échoue. Basic/Important
// n'ont pas ce seuil par catégorie.
func TestEssential_CategoryThreshold(t *testing.T) {
	rs := []assess.ControlResult{
		resCat("GV.OC-01.1", "GV.OC", false, 3, 3), // 3,0
		resCat("GV.OC-02.1", "GV.OC", false, 2, 2), // 2,0 -> moyenne catégorie 2,5
	}
	ess := ComputeConformity(rs, cyfun.LevelEssential)
	if ess.CategoriesConform {
		t.Error("catégorie GV.OC à 2,5 doit être non conforme à Essential (seuil 3)")
	}
	if len(ess.NonConformCategories) != 1 || ess.NonConformCategories[0] != "GV.OC" {
		t.Errorf("catégories non conformes: %v", ess.NonConformCategories)
	}
	if imp := ComputeConformity(rs, cyfun.LevelImportant); !imp.CategoriesConform {
		t.Error("Important ne doit PAS appliquer de seuil par catégorie")
	}
}

// TestAggregate_HierarchicalNotFlat : PREUVE que l'agrégation est celle de la
// CCB (moyenne de moyennes) et non une moyenne à plat. Catégorie A (1 contrôle
// à 1,0) + Catégorie B (3 contrôles à 5,0) :
//   - moyenne à plat      = (1+5+5+5)/4 = 4,0
//   - hiérarchique (CCB)  = moyenne(catA=1,0 ; catB=5,0) = 3,0
func TestAggregate_HierarchicalNotFlat(t *testing.T) {
	rs := []assess.ControlResult{
		resCat("A.X-01.1", "A.X", false, 1, 1),
		resCat("B.Y-01.1", "B.Y", false, 5, 5),
		resCat("B.Y-02.1", "B.Y", false, 5, 5),
		resCat("B.Y-03.1", "B.Y", false, 5, 5),
	}
	if got := ComputeConformity(rs, cyfun.LevelBasic).TotalMaturity; got != 3.0 {
		t.Fatalf("agrégation hiérarchique attendue 3.0 (et non 4.0 à plat), obtenu %v", got)
	}
}

// TestNA_UsesThresholdValue : un contrôle N/A prend la valeur du seuil KM du
// niveau (2,5 Basic ; 3 Important) au lieu de ses scores réels — comme le xlsx.
func TestNA_UsesThresholdValue(t *testing.T) {
	na := resCat("X.Y-01.1", "X.Y", false, 1, 1) // scores 1,1 (ignorés car N/A)
	na.NotApplicable = true
	if got := ComputeConformity([]assess.ControlResult{na}, cyfun.LevelBasic).TotalMaturity; got != 2.5 {
		t.Errorf("N/A Basic attendu 2.5, obtenu %v", got)
	}
	if got := ComputeConformity([]assess.ControlResult{na}, cyfun.LevelImportant).TotalMaturity; got != 3.0 {
		t.Errorf("N/A Important attendu 3.0, obtenu %v", got)
	}
}

// TestNA_KeyMeasurePasses : un Key Measure marqué N/A est conforme (seuil
// substitué), il ne figure pas dans les non-conformes.
func TestNA_KeyMeasurePasses(t *testing.T) {
	na := res("KM", true, 1, 1) // 1,0 -> normalement non conforme
	na.NotApplicable = true
	c := ComputeConformity([]assess.ControlResult{na}, cyfun.LevelBasic)
	if !c.KeyMeasuresConform || len(c.NonConformKeyMeasures) != 0 {
		t.Fatalf("un Key Measure N/A doit être conforme : %+v", c.NonConformKeyMeasures)
	}
}

// randResults génère un jeu de contrôles aléatoire mais DÉTERMINISTE (seed figé).
func randResults(rng *rand.Rand, n int) []assess.ControlResult {
	out := make([]assess.ControlResult, n)
	for i := range out {
		out[i] = res(
			"C"+string(rune('A'+i)),
			rng.Intn(2) == 0,
			cyfun.MaturityLevel(1+rng.Intn(5)),
			cyfun.MaturityLevel(1+rng.Intn(5)),
		)
	}
	return out
}

// PROPRIÉTÉ 1 — pour une catégorie unique (cas de randResults, catégorie vide),
// l'agrégation hiérarchique se réduit à la moyenne des maturités des contrôles.
// Comparaison à epsilon près : diviser-puis-additionner et additionner-puis-
// diviser ne donnent pas le MÊME bit flottant, mais la même valeur réelle.
func TestProp_TotalIsMean(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 500; iter++ {
		rs := randResults(rng, 1+rng.Intn(8))
		var sum cyfun.MaturityScore
		for _, r := range rs {
			sum += r.Maturity()
		}
		want := sum / cyfun.MaturityScore(len(rs))
		got := ComputeConformity(rs, cyfun.LevelBasic).TotalMaturity
		if d := float64(got - want); d > 1e-9 || d < -1e-9 {
			t.Fatalf("total ≠ moyenne (catégorie unique) : got %v want %v", got, want)
		}
	}
}

// PROPRIÉTÉ 2 — MONOTONIE : augmenter l'Implementation d'un contrôle ne baisse
// jamais la maturité totale, et ne fait jamais passer un audit de conforme à
// non conforme.
func TestProp_MonotonicOnImplBump(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for iter := 0; iter < 500; iter++ {
		rs := randResults(rng, 1+rng.Intn(8))
		before := ComputeConformity(rs, cyfun.LevelBasic)

		// on augmente d'un cran l'Impl d'un contrôle au hasard (borné à 5).
		i := rng.Intn(len(rs))
		if rs[i].FinalImpl >= cyfun.Optimizing {
			continue
		}
		bumped := append([]assess.ControlResult(nil), rs...)
		bumped[i].FinalImpl++
		after := ComputeConformity(bumped, cyfun.LevelBasic)

		if after.TotalMaturity < before.TotalMaturity {
			t.Fatalf("monotonie violée : %v -> %v", before.TotalMaturity, after.TotalMaturity)
		}
		if before.Conform && !after.Conform {
			t.Fatalf("augmenter un score a rendu l'audit non conforme")
		}
	}
}

// PROPRIÉTÉ 3 — SEUIL PAR NIVEAU : un seuil plus exigeant ne rend jamais un
// audit non conforme « conforme ». Important (3) est ≥ Basic (2,5).
func TestProp_HigherLevelIsStricter(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for iter := 0; iter < 500; iter++ {
		rs := randResults(rng, 1+rng.Intn(8))
		basic := ComputeConformity(rs, cyfun.LevelBasic)
		important := ComputeConformity(rs, cyfun.LevelImportant)
		// même jeu de contrôles : conforme à Important ⇒ conforme à Basic.
		if important.Conform && !basic.Conform {
			t.Fatalf("conforme au seuil exigeant mais pas au seuil bas : incohérent")
		}
	}
}

// GOLDEN — cas de référence figés : toute évolution changeant un verdict devient
// visible ici.
func TestGolden_Verdicts(t *testing.T) {
	cases := []struct {
		name         string
		level        string
		results      []assess.ControlResult
		wantConform  bool
		wantMaturity cyfun.MaturityScore
	}{
		{"Basic tous KM à 3,0 -> conforme", cyfun.LevelBasic,
			[]assess.ControlResult{res("A", true, 3, 3), res("B", true, 3, 3)}, true, 3.0},
		{"Basic un KM à 2,0 -> NON conforme malgré total 3,5", cyfun.LevelBasic,
			[]assess.ControlResult{res("KM", true, 3, 1), res("X", false, 5, 5)}, false, 3.5},
		{"Basic KM pile à 2,5 -> conforme", cyfun.LevelBasic,
			[]assess.ControlResult{res("KM", true, 3, 2)}, true, 2.5},
		{"Important KM à 2,5 -> NON conforme (seuil 3)", cyfun.LevelImportant,
			[]assess.ControlResult{res("KM", true, 3, 2)}, false, 2.5},
		{"Important KM à 3,0 -> conforme", cyfun.LevelImportant,
			[]assess.ControlResult{res("KM", true, 3, 3)}, true, 3.0},
		{"Essential total 3,0 -> NON conforme (seuil total 3,5)", cyfun.LevelEssential,
			[]assess.ControlResult{resCat("A", "GV.OC", true, 3, 3)}, false, 3.0},
		{"Essential total 4,0 + cat/KM ok -> conforme", cyfun.LevelEssential,
			[]assess.ControlResult{resCat("A", "GV.OC", true, 4, 4), resCat("B", "PR.AA", true, 4, 4)}, true, 4.0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ComputeConformity(c.results, c.level)
			if got.Conform != c.wantConform {
				t.Errorf("conforme = %v, attendu %v", got.Conform, c.wantConform)
			}
			if got.TotalMaturity != c.wantMaturity {
				t.Errorf("maturité = %v, attendu %v", got.TotalMaturity, c.wantMaturity)
			}
		})
	}
}
