package controls

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// ID.AM-08.2 — les patches et mises à jour de sécurité de l'OS et des
// composants critiques doivent être installés. KEY MEASURE (seuil ≥ 2,5).
// Contrôle SCANNABLE : état des mises à jour en attente sur l'hôte.

// PatchEvidence = faits bruts (lecture seule). Windows : Windows Update
// (updates de sécurité en attente, date d'installation la plus récente).
// Linux : apt/dnf (paquets de sécurité upgradables, unattended-upgrades).
type PatchEvidence struct {
	PendingSecurityUpdates int    `json:"pending_security_updates"` // correctifs sécurité en attente
	DaysSinceLastUpdate    int    `json:"days_since_last_update"`   // ancienneté du dernier patch appliqué
	AutoUpdateEnabled      bool   `json:"auto_update_enabled"`      // mises à jour automatiques activées
	Manager                string `json:"manager"`                  // "windows-update", "apt", "dnf"
}

// IDAM0802Meta : métadonnées officielles (texte exact du CCB). Key Measure.
var IDAM0802Meta = cyfun.ControlMeta{
	ID:          "ID.AM-08.2",
	Function:    cyfun.Identify,
	Category:    "ID.AM",
	Subcategory: "ID.AM-08",
	Requirement: "Patches and security updates for operating systems and critical system components shall be installed.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// IDAM0802Questions : volet Documentation (le scan couvre l'Implementation).
var IDAM0802Questions = []survey.Question{
	survey.Ask("ID.AM-08.2", survey.Documentation, "policy",
		"Existe-t-il une procédure écrite de gestion des correctifs (délais d'application, périmètre, responsabilités) ?"),
}

// Seuils de tolérance sur les correctifs. Isolés en constantes pour ajustement
// sans toucher à la logique.
const (
	patchesStaleDays    = 60 // > 60 j sans patch : parc en retard
	patchesToleratedNum = 5  // ≤ 5 correctifs sécurité en attente : toléré transitoirement
)

// --- Normalisation brut → PatchEvidence ---

// winUpdateRaw = JSON émis par la commande Windows Update (voir registry) :
// {"pending":<int>,"auto":<bool>}.
type winUpdateRaw struct {
	Pending *int  `json:"pending"`
	Auto    *bool `json:"auto"`
}

// PatchWindowsNormalizer mappe la sortie Windows Update. L'ancienneté du dernier
// patch n'est pas exposée simplement par l'API COM : on la laisse à 0 (inconnue,
// non pénalisante seule).
func PatchWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w winUpdateRaw
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie Windows Update illisible : %w", err)
	}
	if w.Pending == nil {
		return nil, errors.New("champ pending absent")
	}
	return json.Marshal(PatchEvidence{
		PendingSecurityUpdates: derefInt(w.Pending),
		DaysSinceLastUpdate:    0,
		AutoUpdateEnabled:      derefBool(w.Auto),
		Manager:                "windows-update",
	})
}

// PatchLinuxNormalizer parse la sortie MULTI-DISTRO de shPendingUpdates. La
// commande auto-détecte le gestionnaire (apt/dnf/zypper) et émet 4 lignes :
//  1. nom du gestionnaire ("apt" | "dnf" | "zypper")
//  2. nombre de correctifs de sécurité en attente
//  3. epoch (mtime) du dernier log d'installation
//  4. "yes"/"no" : mises à jour automatiques activées
//
// Horloge injectée pour l'ancienneté.
func PatchLinuxNormalizer(now func() time.Time) assess.NormalizeFunc {
	return func(raw []byte) (json.RawMessage, error) {
		ls := lines(raw)
		if len(ls) < 2 {
			return nil, errors.New("sortie gestionnaire de paquets vide ou incomplète")
		}
		manager := ls[0] // apt | dnf | zypper (émis par la sonde)
		pending, ok := atoiSafe(ls[1])
		if !ok {
			return nil, fmt.Errorf("nombre de correctifs illisible : %q", ls[1])
		}
		days := 0
		if len(ls) > 2 {
			days = ageDaysSinceEpoch(ls[2], now(), 0)
		}
		auto := len(ls) > 3 && ls[3] == "yes"
		return json.Marshal(PatchEvidence{
			PendingSecurityUpdates: pending,
			DaysSinceLastUpdate:    days,
			AutoUpdateEnabled:      auto,
			Manager:                manager,
		})
	}
}

// PatchEvaluator implémente assess.Evaluator pour ID.AM-08.2.
type PatchEvaluator struct{}

// Evaluate : faits de patching d'UN hôte -> constat + niveau proposé. Pure.
func (PatchEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev PatchEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluatePatch(raw.Host, ev)
}

func evaluatePatch(host assess.HostRef, ev PatchEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"pending_security_updates": ev.PendingSecurityUpdates,
			"days_since_last_update":   ev.DaysSinceLastUpdate,
			"auto_update_enabled":      ev.AutoUpdateEnabled,
			"manager":                  ev.Manager,
		},
	}
	manyPending := ev.PendingSecurityUpdates > patchesToleratedNum
	somePending := ev.PendingSecurityUpdates > 0
	stale := ev.DaysSinceLastUpdate > patchesStaleDays

	var lvl cyfun.MaturityLevel
	switch {
	case manyPending || stale:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("Parc en retard : %d correctif(s) sécurité en attente, dernier patch il y a %d j.",
			ev.PendingSecurityUpdates, ev.DaysSinceLastUpdate)
	case somePending:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("%d correctif(s) sécurité en attente (≤ %d toléré transitoirement).",
			ev.PendingSecurityUpdates, patchesToleratedNum)
	case !ev.AutoUpdateEnabled:
		// À jour, mais application manuelle : tenable mais fragile => Defined.
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = "Aucun correctif en attente, mais mises à jour automatiques désactivées (application manuelle)."
	default:
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = "À jour et mises à jour automatiques activées."
	}

	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}
