# Score de risque technique par hôte — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ajouter un indicateur de risque technique par hôte, dérivé uniquement des constats scannés, clairement distinct de la conformité CyFun, affiché au rapport.

**Architecture:** Nouveau paquet pur `internal/risk` calculant un score 0–100 + note A–E par hôte à partir des `ControlResult.HostAssessments` mesurés (pass/partial/fail), Key Measures pondérées plus lourd. `report.Build` consomme ce paquet et l'expose dans la `View` ; un gabarit HTML l'affiche avec un avertissement d'intégrité.

**Tech Stack:** Go (stdlib uniquement), `html/template`, tests `go test`.

## Global Constraints

- Go, binaire **statique CGo-free** — aucune dépendance externe nouvelle (stdlib seulement). Vérifier `CGO_ENABLED=0 go build`.
- Le score de risque est dérivé **UNIQUEMENT** des constats `StatusPass|StatusPartial|StatusFail` (mesurés). Les `StatusNA`, `StatusError`, attestations de repli et contrôles déclaratifs sont **exclus** — intégrité : le risque ne reflète que ce que le scan a constaté.
- Le score de risque **n'est pas** un verdict de conformité CyFun et ne doit jamais entrer dans le calcul de conformité (`session.ComputeConformity`). Il est labellisé comme tel dans toute restitution.
- `gofmt` et `go vet` clean ; tests verts ; commits fréquents.
- Textes en français, commentaires expliquant le « pourquoi » (style du dépôt).

---

### Task 1: Paquet `internal/risk` — calcul du score

**Files:**
- Create: `internal/risk/risk.go`
- Test: `internal/risk/risk_test.go`

**Interfaces:**
- Consumes: `assess.ControlResult`, `assess.HostAssessment`, `assess.Finding`, `assess.Status` (constantes `StatusPass/StatusPartial/StatusFail`), `assess.ControlResult.Meta.KeyMeasure`.
- Produces: `type HostRisk struct{ HostID string; Score int; Grade string; MeasuredControls int; TopContributors []string }` et `func Score(results []assess.ControlResult) []HostRisk`.

- [ ] **Step 1: Écrire le test qui échoue**

```go
package risk

import (
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func res(id string, km bool, host string, st assess.Status) assess.ControlResult {
	return assess.ControlResult{
		Meta: cyfun.ControlMeta{ID: id, KeyMeasure: km},
		HostAssessments: []assess.HostAssessment{{
			Host:     assess.HostRef{ID: host},
			Findings: []assess.Finding{{HostID: host, Status: st, Message: "m"}},
		}},
	}
}

func TestScore_MeasuredOnly_KMWeighted(t *testing.T) {
	results := []assess.ControlResult{
		res("KM-FAIL", true, "PC1", assess.StatusFail),   // pénalise fort
		res("N-PASS", false, "PC1", assess.StatusPass),   // ne pénalise pas
		res("NA", false, "PC1", assess.StatusNA),         // exclu (non mesuré)
		res("N-PASS2", false, "PC2", assess.StatusPass),  // PC2 : aucun risque
	}
	got := Score(results)
	if len(got) != 2 {
		t.Fatalf("attendu 2 hôtes, obtenu %d", len(got))
	}
	// PC1 : pénalité = 2 (KM fail) sur max = 2 (KM) + 1 (normal pass) = 3 -> 67/100.
	if got[0].HostID != "PC1" || got[0].Score != 67 {
		t.Errorf("PC1 : got %+v, attendu score 67", got[0])
	}
	if got[0].MeasuredControls != 2 { // NA exclu
		t.Errorf("PC1 : contrôles mesurés = %d, attendu 2", got[0].MeasuredControls)
	}
	if got[1].HostID != "PC2" || got[1].Score != 0 || got[1].Grade != "A" {
		t.Errorf("PC2 : got %+v, attendu score 0 note A", got[1])
	}
	// Tri : le plus risqué d'abord.
	if got[0].Score < got[1].Score {
		t.Error("les hôtes doivent être triés du plus risqué au moins risqué")
	}
}

func TestScore_IgnoresAttestationAndDeclarative(t *testing.T) {
	results := []assess.ControlResult{
		{Meta: cyfun.ControlMeta{ID: "DECL"}},                       // déclaratif : 0 hôte
		res("SCAN-ERR", true, "PC1", assess.StatusError),            // trou de collecte : exclu
	}
	got := Score(results)
	if len(got) != 0 {
		t.Errorf("aucun constat mesuré : attendu 0 hôte, obtenu %d", len(got))
	}
}
```

- [ ] **Step 2: Lancer le test pour vérifier qu'il échoue**

Run: `go test ./internal/risk/ -run TestScore -v`
Expected: FAIL — le paquet `risk` n'existe pas encore.

- [ ] **Step 3: Écrire l'implémentation minimale**

```go
// Package risk calcule un indicateur de risque TECHNIQUE par hôte à partir des
// constats scannés d'un audit. Ce n'est PAS un verdict de conformité CyFun : c'est
// une aide au triage, dérivée uniquement de ce que le scan a réellement mesuré.
package risk

import (
	"sort"

	"projetcyber/internal/assess"
)

// HostRisk = risque technique d'un hôte. Score 0 = aucun risque mesuré ; 100 = max.
type HostRisk struct {
	HostID           string
	Score            int
	Grade            string
	MeasuredControls int
	TopContributors  []string
}

// Pondérations et pénalités, isolées pour la transparence de l'indice.
const (
	kmWeight       = 2.0
	normalWeight   = 1.0
	penaltyFail    = 1.0
	penaltyPartial = 0.5
	maxContributors = 3
)

// Score calcule le risque par hôte. INTÉGRITÉ : seuls les constats MESURÉS
// (pass/partial/fail) comptent ; n/a, erreurs de collecte, attestations de repli
// et contrôles déclaratifs (sans HostAssessments) sont ignorés.
func Score(results []assess.ControlResult) []HostRisk {
	type acc struct {
		penalty, max float64
		measured     int
		contributors []string
	}
	hosts := map[string]*acc{}
	var order []string
	for _, r := range results {
		weight := normalWeight
		if r.Meta.KeyMeasure {
			weight = kmWeight
		}
		for _, ha := range r.HostAssessments {
			if len(ha.Findings) == 0 {
				continue
			}
			st := ha.Findings[0].Status
			if st != assess.StatusPass && st != assess.StatusPartial && st != assess.StatusFail {
				continue // non mesuré : hors calcul de risque
			}
			a := hosts[ha.Host.ID]
			if a == nil {
				a = &acc{}
				hosts[ha.Host.ID] = a
				order = append(order, ha.Host.ID)
			}
			a.max += weight
			a.measured++
			switch st {
			case assess.StatusFail:
				a.penalty += weight * penaltyFail
				a.contributors = append(a.contributors, r.Meta.ID+" : "+ha.Findings[0].Message)
			case assess.StatusPartial:
				a.penalty += weight * penaltyPartial
				a.contributors = append(a.contributors, r.Meta.ID+" : "+ha.Findings[0].Message)
			}
		}
	}
	out := make([]HostRisk, 0, len(order))
	for _, id := range order {
		a := hosts[id]
		score := 0
		if a.max > 0 {
			score = int((a.penalty/a.max)*100 + 0.5) // arrondi au plus proche
		}
		out = append(out, HostRisk{
			HostID:           id,
			Score:            score,
			Grade:            grade(score),
			MeasuredControls: a.measured,
			TopContributors:  topN(a.contributors, maxContributors),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].HostID < out[j].HostID
	})
	return out
}

func grade(score int) string {
	switch {
	case score <= 20:
		return "A"
	case score <= 40:
		return "B"
	case score <= 60:
		return "C"
	case score <= 80:
		return "D"
	default:
		return "E"
	}
}

func topN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
```

- [ ] **Step 4: Lancer le test pour vérifier qu'il passe**

Run: `go test ./internal/risk/ -run TestScore -v`
Expected: PASS (les deux tests).

- [ ] **Step 5: gofmt + vet + commit**

```bash
gofmt -w internal/risk/
go vet ./internal/risk/
git add internal/risk/
git commit -m "Score de risque technique par hôte (paquet risk, constats scannés seulement)"
```

---

### Task 2: Exposer le risque dans la vue du rapport

**Files:**
- Modify: `internal/report/report.go` (imports ; struct `View` ; fonction `Build`)
- Test: `internal/report/risk_test.go`

**Interfaces:**
- Consumes: `risk.Score([]assess.ControlResult) []risk.HostRisk` (Task 1) ; `session.AuditSession.Results`.
- Produces: champ `View.HostRisks []risk.HostRisk`.

- [ ] **Step 1: Écrire le test qui échoue**

```go
package report

import (
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/session"
)

func TestBuild_PopulatesHostRisks_MeasuredOnly(t *testing.T) {
	results := []assess.ControlResult{
		{
			Meta: cyfun.ControlMeta{ID: "DE.CM-01.2", Function: cyfun.Detect, KeyMeasure: true},
			HostAssessments: []assess.HostAssessment{{
				Host:     assess.HostRef{ID: "PC1"},
				Findings: []assess.Finding{{HostID: "PC1", Status: assess.StatusFail, Message: "pas d'AV"}},
			}},
		},
		{ // attestation de repli : constat NON mesuré, doit être ignoré du risque
			Meta:                cyfun.ControlMeta{ID: "PR.AA-01.1", Function: cyfun.Protect, KeyMeasure: true},
			ImplFromAttestation: true,
			HostAssessments: []assess.HostAssessment{{
				Host:     assess.HostRef{ID: "PC1"},
				Findings: []assess.Finding{{HostID: "PC1", Status: assess.StatusError, Message: "droits insuffisants"}},
			}},
		},
	}
	v := Build(session.AuditSession{Results: results})
	if len(v.HostRisks) != 1 || v.HostRisks[0].HostID != "PC1" {
		t.Fatalf("HostRisks inattendu : %+v", v.HostRisks)
	}
	if v.HostRisks[0].Score != 100 { // un seul constat mesuré, un fail KM -> 100/100
		t.Errorf("score = %d, attendu 100", v.HostRisks[0].Score)
	}
	if v.HostRisks[0].MeasuredControls != 1 { // l'attestation n'est pas comptée
		t.Errorf("contrôles mesurés = %d, attendu 1", v.HostRisks[0].MeasuredControls)
	}
}
```

- [ ] **Step 2: Lancer le test pour vérifier qu'il échoue**

Run: `go test ./internal/report/ -run TestBuild_PopulatesHostRisks -v`
Expected: FAIL — `v.HostRisks` n'existe pas (le champ n'est pas défini).

- [ ] **Step 3: Modifier `report.go`**

Ajouter l'import (bloc d'import existant) :

```go
	"projetcyber/internal/risk"
```

Ajouter le champ à la struct `View` (après `Coverage []CoverageRow`) :

```go
	HostRisks []risk.HostRisk // indicateur de risque technique par hôte (triage, ≠ conformité)
```

Peupler dans `Build`, dans le `return View{...}` (après `Coverage: coverage(s.Results),`) :

```go
		HostRisks: risk.Score(s.Results),
```

- [ ] **Step 4: Lancer le test pour vérifier qu'il passe**

Run: `go test ./internal/report/ -run TestBuild_PopulatesHostRisks -v`
Expected: PASS.

- [ ] **Step 5: gofmt + vet + commit**

```bash
gofmt -w internal/report/
go vet ./internal/report/
git add internal/report/
git commit -m "Rapport : exposer le risque technique par hôte dans la View"
```

---

### Task 3: Section HTML « risque technique par hôte » + avertissement d'intégrité

**Files:**
- Modify: `internal/report/html.go` (gabarit — insérer une section après « 2 bis. Couverture de collecte »)
- Test: `internal/report/risk_html_test.go`

**Interfaces:**
- Consumes: `View.HostRisks` (Task 2), fonction `HTML(View) ([]byte, error)` existante.
- Produces: aucune API nouvelle (rendu seulement).

- [ ] **Step 1: Écrire le test qui échoue**

```go
package report

import (
	"strings"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/session"
)

func TestHTML_RendersHostRiskSectionWithDisclaimer(t *testing.T) {
	results := []assess.ControlResult{{
		Meta: cyfun.ControlMeta{ID: "DE.CM-01.2", Function: cyfun.Detect, KeyMeasure: true},
		HostAssessments: []assess.HostAssessment{{
			Host:     assess.HostRef{ID: "PC1"},
			Findings: []assess.Finding{{HostID: "PC1", Status: assess.StatusFail, Message: "pas d'AV"}},
		}},
	}}
	out, err := HTML(Build(session.AuditSession{Results: results}))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "risque technique") {
		t.Error("la section de risque technique doit être présente")
	}
	if !strings.Contains(s, "PC1") {
		t.Error("l'hôte à risque doit apparaître")
	}
	// Garde-fou d'intégrité : la mention « n'est pas un verdict de conformité » doit figurer.
	if !strings.Contains(strings.ToLower(s), "pas un verdict de conformité") {
		t.Error("l'avertissement d'intégrité (≠ conformité CyFun) doit être affiché")
	}
}
```

- [ ] **Step 2: Lancer le test pour vérifier qu'il échoue**

Run: `go test ./internal/report/ -run TestHTML_RendersHostRiskSection -v`
Expected: FAIL — la section n'existe pas encore dans le gabarit.

- [ ] **Step 3: Insérer la section dans le gabarit `html.go`**

Juste APRÈS le bloc « 2 bis. Couverture de collecte » (avant `<h2>3. Résultats détaillés...`), insérer :

```html
<h2>2 ter. Indicateur de risque technique par hôte</h2>
<p><em>Aide au triage, dérivée UNIQUEMENT des constats scannés (ce qui a été
réellement mesuré sur l'hôte). Ce n'est <strong>pas un verdict de conformité</strong>
CyFun : les attestations de repli, contrôles déclaratifs et trous de collecte n'y
entrent pas. Score 0 = aucun risque mesuré ; 100 = risque maximal.</em></p>
<table>
<tr><th>Hôte</th><th>Risque</th><th>Note</th><th>Contrôles mesurés</th><th>Principaux constats</th></tr>
{{range .HostRisks}}<tr><td>{{.HostID}}</td><td>{{.Score}}/100</td><td>{{.Grade}}</td><td>{{.MeasuredControls}}</td><td><small>{{range .TopContributors}}{{.}}<br>{{end}}</small></td></tr>
{{end}}
</table>
```

- [ ] **Step 4: Lancer le test pour vérifier qu'il passe**

Run: `go test ./internal/report/ -run TestHTML_RendersHostRiskSection -v`
Expected: PASS.

- [ ] **Step 5: Vérifier la non-régression + gofmt + vet + commit**

```bash
go test ./... 2>&1 | grep -vE "no test files"
gofmt -w internal/report/
go vet ./...
CGO_ENABLED=0 go build ./cmd/orchestrator   # confirmer le statique CGo-free
git add internal/report/
git commit -m "Rapport HTML : section risque technique par hôte + avertissement d'intégrité"
```

---

## Hors de ce plan (rappel)

- **Phase 0 — Découverte** : recherche (fan-out d'agents extrayant la guidance CCB Important/Essential → backlog SCAN/MIXTE/ORG par famille). Activité séparée, pas TDD.
- **Familles** : chacune son propre plan, après la découverte.
- **PDF/XLSX du score de risque** : optionnel, plan ultérieur (le HTML est le rapport principal ici).

## Self-Review

- **Couverture spec §4 (score de risque)** : Tasks 1–3 couvrent calcul (mesuré seulement, KM pondéré), exposition, restitution + label d'intégrité. ✓
- **Placeholders** : aucun ; code complet à chaque étape. ✓
- **Cohérence des types** : `HostRisk{HostID, Score, Grade, MeasuredControls, TopContributors}` et `Score(results) []HostRisk` identiques entre Task 1 (définition), Task 2 (consommation), Task 3 (rendu). ✓
- **Intégrité** : exclusion des non-mesurés testée (Task 1 `NA/Error`, Task 2 attestation) ; label « pas un verdict de conformité » testé (Task 3). ✓
