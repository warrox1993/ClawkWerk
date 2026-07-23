package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// PR.AA-05.4 — « No-one shall have administrative privileges for routine
// day-to-day tasks. » KEY MEASURE. Contrôle SCANNABLE : on constate sur l'hôte
// le nombre de comptes disposant de privilèges d'administration locale (proxy
// du moindre privilège) et si le compte administrateur intégré est désactivé.
// Moins il y a d'administrateurs locaux, meilleure est la posture.

// LocalAdminEvidence = faits bruts (lecture seule) sur les comptes à privilèges.
type LocalAdminEvidence struct {
	AdminCount           int  `json:"admin_count"`            // membres du groupe administrateurs local
	BuiltinAdminDisabled bool `json:"builtin_admin_disabled"` // compte Administrator/root intégré désactivé
}

// PRAA0504Meta : texte officiel du CCB. Key Measure.
var PRAA0504Meta = cyfun.ControlMeta{
	ID:          "PR.AA-05.4",
	Function:    cyfun.Protect,
	Category:    "PR.AA",
	Subcategory: "PR.AA-05",
	Requirement: "No-one shall have administrative privileges for routine day-to-day tasks.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// PRAA0504Questions : volet Documentation (le scan couvre l'Implementation).
var PRAA0504Questions = []survey.Question{
	survey.Ask("PR.AA-05.4", survey.Documentation, "policy",
		"Une règle interdit-elle l'usage de comptes à privilèges pour les tâches quotidiennes (comptes admin séparés) ?"),
}

// Seuils sur le nombre d'administrateurs locaux. Isolés en constantes.
const (
	adminsManyThreshold      = 5 // > 5 admins locaux : dispersion des privilèges
	adminsToleratedThreshold = 2 // ≤ 2 : périmètre d'admin maîtrisé
)

// LocalAdminEvaluator implémente assess.Evaluator pour PR.AA-05.4.
type LocalAdminEvaluator struct{}

func (LocalAdminEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev LocalAdminEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateLocalAdmin(raw.Host, ev)
}

func evaluateLocalAdmin(host assess.HostRef, ev LocalAdminEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"admin_count":            ev.AdminCount,
			"builtin_admin_disabled": ev.BuiltinAdminDisabled,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case ev.AdminCount > adminsManyThreshold:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("Trop de comptes administrateurs locaux (%d) : privilèges dispersés.", ev.AdminCount)
	case ev.AdminCount > adminsToleratedThreshold:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("%d comptes administrateurs locaux : à réduire au strict nécessaire.", ev.AdminCount)
	case !ev.BuiltinAdminDisabled:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("Périmètre d'administration réduit (%d), mais compte intégré actif.", ev.AdminCount)
	default:
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = fmt.Sprintf("Administration maîtrisée (%d comptes), compte intégré désactivé.", ev.AdminCount)
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- Normalisation brut → LocalAdminEvidence ---

// LocalAdminWindowsNormalizer parse le JSON émis côté Windows :
// {"admin_count":int,"builtin_admin_disabled":bool}.
func LocalAdminWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		AdminCount           *int  `json:"admin_count"`
		BuiltinAdminDisabled *bool `json:"builtin_admin_disabled"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie comptes admin illisible : %w", err)
	}
	if w.AdminCount == nil {
		return nil, errors.New("champ admin_count absent")
	}
	return json.Marshal(LocalAdminEvidence{
		AdminCount:           derefInt(w.AdminCount),
		BuiltinAdminDisabled: derefBool(w.BuiltinAdminDisabled),
	})
}

// LocalAdminLinuxNormalizer parse 2 lignes : nombre de membres de sudo/wheel ;
// "yes"/"no" indiquant si le compte root est verrouillé.
func LocalAdminLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie comptes admin vide")
	}
	count, ok := atoiSafe(ls[0])
	if !ok {
		return nil, fmt.Errorf("nombre d'administrateurs illisible : %q", ls[0])
	}
	return json.Marshal(LocalAdminEvidence{
		AdminCount:           count,
		BuiltinAdminDisabled: len(ls) > 1 && ls[1] == "yes",
	})
}
