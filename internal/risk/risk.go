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
	kmWeight        = 2.0
	normalWeight    = 1.0
	penaltyFail     = 1.0
	penaltyPartial  = 0.5
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
