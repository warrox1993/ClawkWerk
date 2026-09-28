package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Famille CAPACITÉ/RESSOURCES — PR.IR-04.1 (Important, non-KM, MIXTE). Le scan
// constate un proxy TECHNIQUE de la capacité disponible : le taux d'occupation
// du disque racine (Linux) / du premier volume fixe (Windows). Un disque saturé
// menace directement la disponibilité (journalisation, bases, sauvegardes qui
// échouent faute d'espace). Mais la VRAIE exigence — planifier la capacité
// (processing, réseau, télécoms, stockage) dans la durée — reste
// organisationnelle : elle s'atteste au questionnaire (axe Documentation). Le
// scan plafonne donc à Defined (3) ; le message rappelle que la planification de
// capacité reste organisationnelle.

// CapacityEvidence = faits bruts (lecture seule) sur l'occupation disque.
type CapacityEvidence struct {
	DiskUsagePercent int `json:"disk_usage_percent"` // % d'occupation du volume racine / premier disque fixe
}

// Seuils d'occupation disque. Isolés en constantes pour ajustement sans toucher
// à la logique de décision.
const (
	diskCriticalPercent = 90 // > 90 % : capacité sous tension (risque imminent de saturation)
	diskWarningPercent  = 80 // > 80 % : marge à surveiller
)

// CapacityWinCmd : collecte Windows LECTURE SEULE. Interroge le premier disque
// fixe (DriveType=3) et émet {disk_usage_percent} en JSON.
const CapacityWinCmd = WinPre + `try{$d=New-Object IO.DriveInfo $env:SystemDrive; $p=[int](100-($d.AvailableFreeSpace/$d.TotalSize*100))}catch{F 'volume systeme' $_}; [pscustomobject]@{disk_usage_percent=$p}|ConvertTo-Json`

// CapacityLinuxCmd : collecte Linux LECTURE SEULE. Émet 1 ligne = le % d'usage
// du disque racine (colonne « Use% » de df, sans le signe %).
const CapacityLinuxCmd = `df -P / 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}'`

// PRIR0401Meta : texte officiel du CCB (Important, non Key Measure).
var PRIR0401Meta = cyfun.ControlMeta{
	ID: "PR.IR-04.1", Function: cyfun.Protect, Category: "PR.IR", Subcategory: "PR.IR-04",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "Adequate resource capacity planning shall ensure that availability of organisation's critical system information processing, networking, telecommunications, and data storage is maintained.",
}

// PRIR0401Questions : volet Documentation (le scan couvre l'Implementation).
var PRIR0401Questions = []survey.Question{
	survey.Ask("PR.IR-04.1", survey.Documentation, "policy",
		"La planification de la capacité des ressources (traitement, réseau, télécoms, stockage) est-elle documentée, approuvée et revue ?"),
}

// CapacityEvaluator implémente assess.Evaluator pour PR.IR-04.1.
type CapacityEvaluator struct{}

func (CapacityEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev CapacityEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateCapacity(raw.Host, ev)
}

// evaluateCapacity contient la règle de décision, séparée du (dé)codage pour
// rester trivialement testable sur des faits typés. Fonction PURE. MIXTE :
// plafond Defined, car la planification de capacité reste organisationnelle.
func evaluateCapacity(host assess.HostRef, ev CapacityEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{"disk_usage_percent": ev.DiskUsagePercent},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case ev.DiskUsagePercent > diskCriticalPercent:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("disque à %d%% — capacité sous tension", ev.DiskUsagePercent)
	case ev.DiskUsagePercent > diskWarningPercent:
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = fmt.Sprintf("disque à %d%% — marge de capacité à surveiller", ev.DiskUsagePercent)
	default:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("capacité disque saine (%d%%)", ev.DiskUsagePercent)
	}
	if lvl > cyfun.Defined { // plafond MIXTE : le scan ne dépasse pas Defined.
		lvl = cyfun.Defined
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message + " ; la planification de capacité reste organisationnelle (à attester).",
	}
}

// --- Normalisation brut → CapacityEvidence ---

// CapacityWindowsNormalizer parse le JSON émis côté Windows :
// {"disk_usage_percent":int}.
func CapacityWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		DiskUsagePercent *int `json:"disk_usage_percent"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie capacité disque illisible : %w", err)
	}
	if w.DiskUsagePercent == nil {
		return nil, errors.New("champ disk_usage_percent absent")
	}
	return json.Marshal(CapacityEvidence{DiskUsagePercent: derefInt(w.DiskUsagePercent)})
}

// CapacityLinuxNormalizer parse 1 ligne : le % entier d'occupation du disque
// racine. Erreur si la sortie est vide ou illisible.
func CapacityLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie capacité disque vide")
	}
	pct, ok := atoiSafe(ls[0])
	if !ok {
		return nil, fmt.Errorf("taux d'occupation disque illisible : %q", ls[0])
	}
	return json.Marshal(CapacityEvidence{DiskUsagePercent: pct})
}
