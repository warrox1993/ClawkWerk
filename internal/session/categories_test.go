package session

import (
	"math"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// Valeurs de référence calculées par l'outil officiel BASIC du CCB
// (CyFun2025_ Self-Assessment_tool_BASIC_v2026_02_20.xlsx, recalculé par
// LibreOffice le 28/09/2026) pour la catégorie PR.AA : PR.AA-01.1 (4,5),
// PR.AA-03.1 (2,1), PR.AA-03.2 (N/A), PR.AA-06.1 (3,3).
// Onglet PROTECT : H/I par sous-catégorie, J/K par catégorie ; onglet Summary :
// D = moyenne(E, F). N/A = seuil Key Measure (2,5) sur les deux axes.
func TestCategories_CommeLOutilOfficiel(t *testing.T) {
	r := func(id, sub string, d, i cyfun.MaturityLevel, na bool) assess.ControlResult {
		return assess.ControlResult{Meta: cyfun.ControlMeta{ID: id, Function: cyfun.Protect, Category: "PR.AA", Subcategory: sub},
			FinalDoc: d, FinalImpl: i, NotApplicable: na}
	}
	res := []assess.ControlResult{
		r("PR.AA-01.1", "PR.AA-01", 4, 5, false),
		r("PR.AA-03.1", "PR.AA-03", 2, 1, false),
		r("PR.AA-03.2", "PR.AA-03", 0, 0, true),
		r("PR.AA-06.1", "PR.AA-06", 3, 3, false),
	}
	c := ComputeConformity(res, cyfun.LevelBasic)
	if len(c.Categories) != 1 {
		t.Fatalf("catégories : %+v", c.Categories)
	}
	got := c.Categories[0]
	// Doc : sous-catégories 4 ; (2+2,5)/2 = 2,25 ; 3 → 9,25/3. Impl : 5 ; 1,75 ; 3 → 9,75/3.
	wantDoc, wantImpl := 9.25/3, 9.75/3
	near := func(a cyfun.MaturityScore, b float64) bool { return math.Abs(float64(a)-b) < 1e-12 }
	if !near(got.Documentation, wantDoc) || !near(got.Implementation, wantImpl) || !near(got.Maturity, (wantDoc+wantImpl)/2) {
		t.Fatalf("PR.AA : %+v, attendu doc %.6f impl %.6f", got, wantDoc, wantImpl)
	}
	if !near(c.TotalMaturity, (wantDoc+wantImpl)/2) || got.Function != "PROTECT" {
		t.Fatalf("total %.6f / fonction %q", c.TotalMaturity, got.Function)
	}
}
