// Package report transforme une session.AuditSession en livrables destinés au
// client : un rapport HTML lisible et un classeur XLSX exploitable. Les deux
// générateurs n'utilisent QUE la bibliothèque standard (html/template,
// archive/zip, encoding/xml) — pas de dépendance externe, cohérent avec la
// livraison en binaire statique unique.
//
// Le rapport ne DÉCIDE de rien : il met en forme la session déjà calculée
// (scores, conformité, journal). Toute logique de scoring reste en amont.
package report

import (
	"fmt"
	"sort"
	"strings"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/risk"
	"projetcyber/internal/session"
)

// ordre d'affichage des fonctions NIST (celui du référentiel CyFun).
var functionOrder = []cyfun.Function{
	cyfun.Govern, cyfun.Identify, cyfun.Protect,
	cyfun.Detect, cyfun.Respond, cyfun.Recover,
}

// FunctionGroup = un bloc "résultats détaillés" par fonction NIST.
type FunctionGroup struct {
	Function cyfun.Function
	Controls []ControlView
}

// ControlView = une ligne de résultat enrichie pour l'affichage : scores,
// maturité, verdict individuel, preuve saillante et écart au seuil.
type ControlView struct {
	Meta           cyfun.ControlMeta
	Doc            cyfun.MaturityLevel
	Impl           cyfun.MaturityLevel
	Maturity       cyfun.MaturityScore
	Conform        bool                // pour un Key Measure : atteint-il 2,5 ?
	Evidence       string              // constat le plus représentatif (preuve)
	Gap            cyfun.MaturityScore // manque pour atteindre le seuil KM (0 si OK/non-KM)
	Declared       bool                // contrôle déclaratif (pas de scan)
	Overridden     bool                // l'Implementation a été corrigée par le consultant
	OverrideReason string              // justification de l'override (preuve d'audit)
	ProposedImpl   cyfun.MaturityLevel // valeur d'origine (scan/questionnaire) avant override
	ExcellenceGap  cyfun.MaturityScore // manque pour atteindre 5/5 (0 si déjà au max)
	NotApplicable  bool                // contrôle attesté « non applicable »
}

// RemediationItem = une entrée du plan de remédiation priorisé.
type RemediationItem struct {
	ControlView
	Priority int // 1 = le plus urgent
}

// CoverageRow = une ligne de la matrice de COUVERTURE DE COLLECTE : comment un
// contrôle a réellement été évalué (scan technique, attestation de repli,
// déclaratif, N/A, ou non évalué) et, le cas échéant, pourquoi il reste des
// trous (OS non supporté, droits insuffisants, hôte injoignable). C'est
// l'honnêteté d'audit rendue visible : jamais un « scanné » qui ne l'a pas été.
type CoverageRow struct {
	Function cyfun.Function
	ID       string
	Method   string
	Detail   string
}

// View = modèle complet passé aux gabarits/générateurs.
type View struct {
	Session     session.AuditSession
	Groups      []FunctionGroup
	Remediation []RemediationItem
	// Excellence = contrôles pas encore au niveau 5, du plus faible au plus fort :
	// la feuille de route vers le 5/5 (objectif d'amélioration, phase remédiation).
	Excellence []ControlView
	Level5     string        // texte officiel du niveau 5 (ce qu'il faut démontrer)
	Coverage   []CoverageRow // couverture de collecte, dans l'ordre des fonctions NIST
	// HostRisks = indicateur de risque TECHNIQUE par hôte (constats scannés
	// seulement) — aide au triage, distincte du verdict de conformité CyFun.
	HostRisks []risk.HostRisk
}

// Build projette une session en modèle de vue : regroupe les contrôles par
// fonction NIST (ordre du référentiel) et construit le plan de remédiation.
func Build(s session.AuditSession) View {
	// Seuils du NIVEAU audité : la conformité PAR CONTRÔLE (Key Measure) utilise
	// le seuil KM ; le plan de remédiation compare aussi à la maturité TOTALE.
	kmThreshold := s.Conformity.KeyMeasureThreshold
	totalThreshold := s.Conformity.TotalThreshold
	byFunc := make(map[cyfun.Function][]ControlView)
	for _, r := range s.Results {
		cv := toControlView(r, kmThreshold)
		byFunc[r.Meta.Function] = append(byFunc[r.Meta.Function], cv)
	}

	var groups []FunctionGroup
	for _, fn := range functionOrder {
		cvs := byFunc[fn]
		if len(cvs) == 0 {
			continue
		}
		// tri stable par ID de contrôle à l'intérieur d'une fonction.
		sort.Slice(cvs, func(i, j int) bool { return cvs[i].Meta.ID < cvs[j].Meta.ID })
		groups = append(groups, FunctionGroup{Function: fn, Controls: cvs})
	}

	// Feuille de route vers l'excellence : tout contrôle sous 5/5, du plus faible
	// au plus fort (le plus de marge d'abord).
	var excellence []ControlView
	for _, g := range groups {
		for _, cv := range g.Controls {
			if cv.ExcellenceGap > 0 {
				excellence = append(excellence, cv)
			}
		}
	}
	sort.SliceStable(excellence, func(i, j int) bool {
		if excellence[i].Maturity != excellence[j].Maturity {
			return excellence[i].Maturity < excellence[j].Maturity
		}
		return excellence[i].Meta.ID < excellence[j].Meta.ID
	})

	return View{
		Session:     s,
		Groups:      groups,
		Remediation: remediationPlan(s.Results, kmThreshold, totalThreshold),
		Excellence:  excellence,
		Level5:      cyfun.MaturityRubric[cyfun.Optimizing],
		Coverage:    coverage(s.Results),
		HostRisks:   risk.Score(s.Results),
	}
}

// coverage construit la matrice de couverture de collecte, dans l'ordre des
// fonctions NIST puis par ID de contrôle.
func coverage(results []assess.ControlResult) []CoverageRow {
	rows := make([]CoverageRow, 0, len(results))
	for _, r := range results {
		rows = append(rows, coverageRow(r))
	}
	order := map[cyfun.Function]int{}
	for i, fn := range functionOrder {
		order[fn] = i
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if order[rows[i].Function] != order[rows[j].Function] {
			return order[rows[i].Function] < order[rows[j].Function]
		}
		return rows[i].ID < rows[j].ID
	})
	return rows
}

// coverageRow classe UN contrôle : méthode d'évaluation réelle + détail des trous.
func coverageRow(r assess.ControlResult) CoverageRow {
	row := CoverageRow{Function: r.Meta.Function, ID: r.Meta.ID}
	switch {
	case r.NotApplicable:
		row.Method = "N/A (attesté)"
		return row
	case len(r.HostAssessments) == 0:
		row.Method = "Déclaratif (questionnaire)"
		return row
	}
	// Contrôle scannable : on compte les hôtes réellement MESURÉS vs les trous.
	measured := 0
	var gaps []string
	for _, ha := range r.HostAssessments {
		switch hostStatus(ha) {
		case assess.StatusPass, assess.StatusPartial, assess.StatusFail:
			measured++
		default: // StatusNA (OS non supporté) ou StatusError (droits/injoignable)
			gaps = append(gaps, ha.Host.ID+" ("+gapReason(ha)+")")
		}
	}
	switch {
	case r.ImplFromAttestation:
		row.Method = "Attestation de repli (scan indisponible)"
	case measured == 0:
		row.Method = "NON ÉVALUÉ"
	default:
		row.Method = "Scan technique"
	}
	var parts []string
	if measured > 0 {
		parts = append(parts, fmt.Sprintf("%d hôte(s) mesuré(s)", measured))
	}
	if len(gaps) > 0 {
		parts = append(parts, fmt.Sprintf("%d trou(s) : %s", len(gaps), strings.Join(gaps, ", ")))
	}
	row.Detail = strings.Join(parts, " ; ")
	return row
}

// hostStatus renvoie le statut du premier constat d'un hôte (nos contrôles en
// produisent un par hôte).
func hostStatus(ha assess.HostAssessment) assess.Status {
	if len(ha.Findings) > 0 {
		return ha.Findings[0].Status
	}
	return assess.StatusError
}

// gapReason qualifie un trou de collecte pour un hôte : OS non supporté, droits
// insuffisants, ou hôte injoignable / preuve illisible.
func gapReason(ha assess.HostAssessment) string {
	if len(ha.Findings) == 0 {
		return "aucun constat"
	}
	f := ha.Findings[0]
	if f.Status == assess.StatusNA {
		return "OS non supporté"
	}
	if strings.Contains(strings.ToLower(f.Message), "droits insuffisants") {
		return "droits insuffisants"
	}
	return "injoignable / preuve illisible"
}

// toControlView enrichit un ControlResult pour l'affichage, au seuil du niveau.
func toControlView(r assess.ControlResult, threshold cyfun.MaturityScore) ControlView {
	cv := ControlView{
		Meta:           r.Meta,
		Doc:            r.FinalDoc,
		Impl:           r.FinalImpl,
		Maturity:       r.Maturity(),
		Conform:        r.ConformAt(threshold),
		Evidence:       representativeEvidence(r),
		Declared:       len(r.HostAssessments) == 0,
		Overridden:     r.ImplOverridden,
		OverrideReason: r.OverrideReason,
		ProposedImpl:   r.ProposedImpl,
		NotApplicable:  r.NotApplicable,
	}
	if r.Meta.KeyMeasure && r.Maturity() < threshold {
		cv.Gap = threshold - r.Maturity()
	}
	// Écart à l'excellence (5/5) : ce qui reste à démontrer pour le niveau max.
	if r.Maturity() < 5 {
		cv.ExcellenceGap = 5 - r.Maturity()
	}
	return cv
}

// representativeEvidence choisit une phrase de preuve : le premier constat le
// plus grave parmi les hôtes (fail > partial > pass). Vide pour un déclaratif.
func representativeEvidence(r assess.ControlResult) string {
	rank := map[assess.Status]int{
		assess.StatusError: 4, assess.StatusFail: 3,
		assess.StatusPartial: 2, assess.StatusNA: 1, assess.StatusPass: 0,
	}
	best, bestRank := "", -1
	for _, ha := range r.HostAssessments {
		for _, f := range ha.Findings {
			if rank[f.Status] > bestRank {
				best, bestRank = f.HostID+" : "+f.Message, rank[f.Status]
			}
		}
	}
	return best
}

// remediationPlan trie les contrôles à corriger par urgence : d'abord les Key
// Measures non conformes (ils bloquent la conformité), puis les autres
// contrôles sous le seuil total, du plus faible au plus fort. Les contrôles
// déjà au niveau ne figurent pas dans le plan.
func remediationPlan(results []assess.ControlResult, kmThreshold, totalThreshold cyfun.MaturityScore) []RemediationItem {
	var items []RemediationItem
	for _, r := range results {
		cv := toControlView(r, kmThreshold)
		blockingKM := r.Meta.KeyMeasure && !r.ConformAt(kmThreshold)
		belowTotal := r.Maturity() < totalThreshold
		if !blockingKM && !belowTotal {
			continue // rien à remédier
		}
		items = append(items, RemediationItem{ControlView: cv})
	}
	// urgence : KM bloquant d'abord, puis maturité croissante, puis ID stable.
	sort.SliceStable(items, func(i, j int) bool {
		ki := items[i].Meta.KeyMeasure && !items[i].Conform
		kj := items[j].Meta.KeyMeasure && !items[j].Conform
		if ki != kj {
			return ki // les KM bloquants remontent
		}
		if items[i].Maturity != items[j].Maturity {
			return items[i].Maturity < items[j].Maturity
		}
		return items[i].Meta.ID < items[j].Meta.ID
	})
	for i := range items {
		items[i].Priority = i + 1
	}
	return items
}
