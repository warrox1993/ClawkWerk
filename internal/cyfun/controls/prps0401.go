package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// PR.PS-04.1 — « Logs shall be maintained, documented, and monitored. »
// KEY MEASURE. Contrôle SCANNABLE : on constate sur l'hôte que la
// journalisation est active, conservée assez longtemps, et idéalement
// centralisée/transférée. La Documentation vient du questionnaire.

// LoggingEvidence = faits bruts (lecture seule) de l'état de journalisation.
type LoggingEvidence struct {
	Enabled       bool `json:"enabled"`        // service de journalisation actif
	RetentionDays int  `json:"retention_days"` // durée de conservation configurée
	Forwarding    bool `json:"forwarding"`     // journaux transférés/centralisés
}

// PRPS0401Meta : métadonnées officielles (texte exact du CCB). Key Measure.
var PRPS0401Meta = cyfun.ControlMeta{
	ID:          "PR.PS-04.1",
	Function:    cyfun.Protect,
	Category:    "PR.PS",
	Subcategory: "PR.PS-04",
	Requirement: "Logs shall be maintained, documented, and monitored.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// PRPS0401Questions : volet Documentation (le scan couvre l'Implementation).
var PRPS0401Questions = []survey.Question{
	survey.Ask("PR.PS-04.1", survey.Documentation, "policy",
		"Une procédure définit-elle quels journaux sont conservés, combien de temps, et comment ils sont revus ?"),
}

// Seuils de conservation (jours). Isolés en constantes.
const (
	logRetentionShortDays = 30 // < 30 j : conservation trop courte
	logRetentionGoodDays  = 90 // ≥ 90 j : conservation confortable
)

// LoggingEvaluator implémente assess.Evaluator pour PR.PS-04.1.
type LoggingEvaluator struct{}

// Evaluate : faits de journalisation d'UN hôte -> constat + niveau proposé. Pure.
func (LoggingEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev LoggingEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateLogging(raw.Host, ev)
}

func evaluateLogging(host assess.HostRef, ev LoggingEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"enabled":        ev.Enabled,
			"retention_days": ev.RetentionDays,
			"forwarding":     ev.Forwarding,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case !ev.Enabled:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Journalisation désactivée."
	case ev.RetentionDays < logRetentionShortDays:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("Conservation des journaux trop courte (%d j < %d j).", ev.RetentionDays, logRetentionShortDays)
	case ev.RetentionDays < logRetentionGoodDays || !ev.Forwarding:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("Journalisation active, conservée %d j, sans centralisation.", ev.RetentionDays)
	default:
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = fmt.Sprintf("Journalisation active, centralisée, conservée %d j (≥ %d j).", ev.RetentionDays, logRetentionGoodDays)
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- Normalisation brut → LoggingEvidence ---

// LoggingWindowsNormalizer parse le JSON émis côté Windows :
// {"enabled":bool,"retention_days":int,"forwarding":bool}.
func LoggingWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		Enabled       *bool `json:"enabled"`
		RetentionDays *int  `json:"retention_days"`
		Forwarding    *bool `json:"forwarding"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie journalisation illisible : %w", err)
	}
	if w.Enabled == nil {
		return nil, errors.New("champ enabled absent")
	}
	return json.Marshal(LoggingEvidence{
		Enabled:       derefBool(w.Enabled),
		RetentionDays: derefInt(w.RetentionDays),
		Forwarding:    derefBool(w.Forwarding),
	})
}

// LoggingLinuxNormalizer parse 3 lignes : état du service (active/inactive) ;
// durée de conservation en jours ; "yes"/"no" pour le transfert distant.
func LoggingLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie journalisation vide")
	}
	retention := 0
	if len(ls) > 1 {
		retention, _ = atoiSafe(ls[1])
	}
	return json.Marshal(LoggingEvidence{
		Enabled:       ls[0] == "active",
		RetentionDays: retention,
		Forwarding:    len(ls) > 2 && ls[2] == "yes",
	})
}
