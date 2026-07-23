package controls

import (
	"encoding/json"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// PR.IR-01.2 — segmentation et cloisonnement réseau (Key Measure), promu
// SCANNABLE via le framework netdevice. On constate sur l'équipement le nombre
// de segments (VLAN / zones) et, quand c'est observable, l'existence d'un
// filtrage inter-segments. La Documentation vient du questionnaire.
//
// Honnêteté : le filtrage inter-segments est difficile à établir par une seule
// commande ; le scan plafonne donc à « Defined » (le niveau « Managed »
// suppose une preuve organisationnelle — matrice de flux, revue — qui relève du
// questionnaire, pas d'un endpoint).

// SegmentationEvidence = posture de segmentation, forme canonique commune.
type SegmentationEvidence struct {
	Present               bool `json:"present"`                 // l'équipement gère des segments
	Segments              int  `json:"segments"`                // nb de VLAN / zones distincts
	InterSegmentFiltering bool `json:"inter_segment_filtering"` // filtrage entre segments constaté
}

// PRIR0102Meta : texte officiel du CCB. Key Measure.
var PRIR0102Meta = cyfun.ControlMeta{
	ID:          "PR.IR-01.2",
	Function:    cyfun.Protect,
	Category:    "PR.IR",
	Subcategory: "PR.IR-01",
	Requirement: "To safeguard critical systems, organisations shall implement network segmentation and segregation aligned with trust boundaries and asset criticality, thereby limiting threat propagation and enforcing strict access control.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// PRIR0102Questions : volet Documentation (le scan couvre l'Implementation).
var PRIR0102Questions = []survey.Question{
	survey.Ask("PR.IR-01.2", survey.Documentation, "policy",
		"Une segmentation réseau alignée sur la criticité des actifs est-elle conçue et documentée (plan d'adressage, matrice de flux) ?"),
}

// seuil : au-delà, on considère une segmentation « réelle » (plusieurs zones).
const segRealSegments = 3

// NetSegmentationEvaluator implémente assess.Evaluator pour PR.IR-01.2.
type NetSegmentationEvaluator struct{}

func (NetSegmentationEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev SegmentationEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateSegmentation(raw.Host, ev)
}

func evaluateSegmentation(host assess.HostRef, ev SegmentationEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"present":                 ev.Present,
			"segments":                ev.Segments,
			"inter_segment_filtering": ev.InterSegmentFiltering,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case !ev.Present || ev.Segments <= 1:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Réseau plat : aucune segmentation détectée."
	case ev.Segments < segRealSegments:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("Segmentation minimale (%d segments) — cloisonnement limité.", ev.Segments)
	case !ev.InterSegmentFiltering:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("%d segments définis mais filtrage inter-segments non constaté.", ev.Segments)
	default:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("Segmentation en place (%d segments) avec filtrage inter-segments.", ev.Segments)
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}
