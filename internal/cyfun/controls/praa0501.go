package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// PR.AA-05.1 — « Access permissions, rights, and authorisations shall be defined,
// managed, enforced and reviewed. » KEY MEASURE. Contrôle SCANNABLE mais preuve
// PARTIELLE : le scan ne peut constater qu'un SIGNAL technique d'une revue des
// accès défaillante — les comptes activés qui ne se sont JAMAIS connectés ou
// dormants. Beaucoup de comptes inactifs = personne ne revoit ni ne révoque les
// droits. En revanche, la revue périodique FORMELLE (procédure documentée,
// propriétaire, cadence) est d'ordre ORGANISATIONNEL : elle ne se lit pas sur
// l'hôte. Le scan plafonne donc à Defined (3), et le message rappelle toujours
// que la revue périodique formelle reste à attester par preuve organisationnelle.

// AccessReviewEvidence = faits bruts (lecture seule) sur l'hygiène des comptes.
type AccessReviewEvidence struct {
	InactiveAccounts   int `json:"inactive_accounts"`    // comptes activés jamais connectés / dormants
	TotalLocalAccounts int `json:"total_local_accounts"` // comptes locaux énumérés
}

// PRAA0501Meta : texte officiel du CCB. Key Measure.
var PRAA0501Meta = cyfun.ControlMeta{
	ID:          "PR.AA-05.1",
	Function:    cyfun.Protect,
	Category:    "PR.AA",
	Subcategory: "PR.AA-05",
	Requirement: "Access permissions, rights, and authorisations shall be defined, managed, enforced and reviewed.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// PRAA0501Questions : volet Documentation. Le scan ne fournit qu'une preuve
// partielle ; la revue périodique formelle s'atteste ici.
var PRAA0501Questions = []survey.Question{
	survey.Ask("PR.AA-05.1", survey.Documentation, "policy",
		"Les droits d'accès sont-ils définis, attribués par propriétaire et REVUS périodiquement selon une procédure documentée ?"),
}

// Seuil au-delà duquel le nombre de comptes dormants trahit une revue absente.
const inactiveAccountsManyThreshold = 5

// AccessReviewEvaluator implémente assess.Evaluator pour PR.AA-05.1.
type AccessReviewEvaluator struct{}

func (AccessReviewEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev AccessReviewEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateAccessReview(raw.Host, ev)
}

// evaluateAccessReview : règle de décision pure. PREUVE PARTIELLE — le niveau
// plafonne à Defined (3), la revue périodique formelle restant organisationnelle.
func evaluateAccessReview(host assess.HostRef, ev AccessReviewEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"inactive_accounts":    ev.InactiveAccounts,
			"total_local_accounts": ev.TotalLocalAccounts,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case ev.TotalLocalAccounts <= 0:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Énumération des comptes impossible ; revue des accès non vérifiable."
	case ev.InactiveAccounts > inactiveAccountsManyThreshold:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("%d comptes inactifs/dormants — revue des accès insuffisante ; revue périodique formelle à attester (preuve organisationnelle).", ev.InactiveAccounts)
	case ev.InactiveAccounts > 0:
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = fmt.Sprintf("%d comptes inactifs ; revue périodique formelle à attester (preuve organisationnelle).", ev.InactiveAccounts)
	default:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = "Aucun compte dormant ; revue périodique formelle à attester (preuve organisationnelle)."
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// PRAA0501WinCmd : collecte Windows LECTURE SEULE, émet du JSON. Get-LocalUser,
// avec repli WMI Win32_UserAccount pour compatibilité Windows 7. Compte les
// comptes activés n'ayant jamais eu de LastLogon (dormants).
const PRAA0501WinCmd = `$all=@(Get-LocalUser -ErrorAction SilentlyContinue); if(-not $all){ $all=@(Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue) }; $inactive=@($all | Where-Object {$_.Enabled -and -not $_.LastLogon}).Count; [pscustomobject]@{inactive_accounts=$inactive; total_local_accounts=$all.Count} | ConvertTo-Json`

// PRAA0501LinuxCmd : collecte Linux LECTURE SEULE, émet 2 lignes : nombre de
// comptes humains (UID 1000..65533), puis nombre de comptes jamais connectés.
const PRAA0501LinuxCmd = `getent passwd 2>/dev/null | awk -F: '$3>=1000 && $3<65534 {c++} END{print c+0}'; lastlog 2>/dev/null | awk 'NR>1 && /Never logged in/ {c++} END{print c+0}'`

// --- Normalisation brut → AccessReviewEvidence ---

// AccessReviewWindowsNormalizer parse le JSON émis côté Windows :
// {"inactive_accounts":int,"total_local_accounts":int}.
func AccessReviewWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		InactiveAccounts   *int `json:"inactive_accounts"`
		TotalLocalAccounts *int `json:"total_local_accounts"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie comptes locaux illisible : %w", err)
	}
	if w.TotalLocalAccounts == nil {
		return nil, errors.New("champ total_local_accounts absent")
	}
	return json.Marshal(AccessReviewEvidence{
		InactiveAccounts:   derefInt(w.InactiveAccounts),
		TotalLocalAccounts: derefInt(w.TotalLocalAccounts),
	})
}

// AccessReviewLinuxNormalizer parse 2 lignes : ligne[0]=TotalLocalAccounts,
// ligne[1]=InactiveAccounts.
func AccessReviewLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie comptes locaux vide")
	}
	total, ok := atoiSafe(ls[0])
	if !ok {
		return nil, fmt.Errorf("nombre de comptes illisible : %q", ls[0])
	}
	ev := AccessReviewEvidence{TotalLocalAccounts: total}
	if len(ls) > 1 {
		if v, ok := atoiSafe(ls[1]); ok {
			ev.InactiveAccounts = v
		}
	}
	return json.Marshal(ev)
}
