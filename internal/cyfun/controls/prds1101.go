package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// PR.DS-11.1 — « Backups for the organisation's business-critical data shall be
// performed and stored on a different system from the device on which the
// original data resides. » KEY MEASURE. Contrôle SCANNABLE : on constate sur
// l'hôte la POSTURE technique de sauvegarde — présence d'une solution de
// backup, existence d'une tâche planifiée, et indice d'une destination
// distincte/hors-site. Le caractère réellement « hors-site » d'une destination
// n'étant pas prouvable de façon fiable en lecture seule depuis l'hôte source,
// le scan plafonne à Managed (4) : le niveau Optimizing (5) s'atteste par
// preuve organisationnelle (test de restauration documenté, override tracé).

// BackupEvidence = faits bruts (lecture seule) sur la posture de sauvegarde.
type BackupEvidence struct {
	SolutionPresent   bool `json:"solution_present"`   // une solution de sauvegarde est installée
	ScheduledJob      bool `json:"scheduled_job"`      // une sauvegarde planifiée existe
	OffsiteConfigured bool `json:"offsite_configured"` // destination distincte/hors-site configurée
}

// PRDS1101Meta : texte officiel du CCB. Key Measure.
var PRDS1101Meta = cyfun.ControlMeta{
	ID:          "PR.DS-11.1",
	Function:    cyfun.Protect,
	Category:    "PR.DS",
	Subcategory: "PR.DS-11",
	Requirement: "Backups for the organisation's business-critical data shall be performed and stored on a different system from the device on which the original data resides.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// PRDS1101Questions : volet Documentation (le scan couvre l'Implementation).
var PRDS1101Questions = []survey.Question{
	survey.Ask("PR.DS-11.1", survey.Documentation, "policy",
		"Une politique de sauvegarde des données critiques (fréquence, système distinct, test de restauration) est-elle documentée ?"),
}

// PRDS1101WinCmd : sonde Windows LECTURE SEULE (JSON). Détecte un service de
// sauvegarde connu (wbengine/Veeam/Backup/Acronis) et une tâche planifiée dont
// le nom évoque une sauvegarde (schtasks downlevel). Le caractère hors-site
// n'est pas déductible ici : offsite_configured=false, à confirmer au
// questionnaire.
const PRDS1101WinCmd = WinPre + `$re='Veeam|Acronis|BackupExec|Datto|Cohesity|Rubrik|Commvault|GxCVD|Carbonite|Nakivo|UrBackup|Macrium|Arcserve|Duplicati|Altaro|Druva'; ` + WinAutoServices + `$t=@(schtasks /query /fo csv /nh 2>$null|ConvertFrom-Csv -Header n,d,s|?{$_.n -notlike '\Microsoft\*' -and $_.n -match 'backup|sauvegarde|restic|veeam'}); [pscustomobject]@{solution_present=($S.Count -gt 0); scheduled_job=($t.Count -gt 0); offsite_configured=$false}|ConvertTo-Json`

// PRDS1101LinuxCmd : sonde Linux LECTURE SEULE (3 lignes yes/no) — présence
// d'un outil de sauvegarde, existence d'une planification (cron/timer), et
// indice hors-site (toujours "no" : non prouvable depuis l'hôte source).
const PRDS1101LinuxCmd = `command -v restic borg duplicity rsnapshot bacula-fd 2>/dev/null | grep -q . && echo yes || echo no; (crontab -l 2>/dev/null; ls /etc/cron.d /etc/cron.daily 2>/dev/null; systemctl list-timers 2>/dev/null) | grep -v dpkg-db-backup | grep -qiE 'backup|restic|borg|duplicity|rsnapshot' && echo yes || echo no; echo no`

// BackupEvaluator implémente assess.Evaluator pour PR.DS-11.1.
type BackupEvaluator struct{}

func (BackupEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev BackupEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateBackup(raw.Host, ev)
}

func evaluateBackup(host assess.HostRef, ev BackupEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"solution_present":   ev.SolutionPresent,
			"scheduled_job":      ev.ScheduledJob,
			"offsite_configured": ev.OffsiteConfigured,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case !ev.SolutionPresent:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Aucune solution de sauvegarde détectée."
	case !ev.ScheduledJob:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = "Solution de sauvegarde présente mais aucune sauvegarde planifiée."
	case !ev.OffsiteConfigured:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = "Sauvegardes planifiées ; destination distincte/hors-site à confirmer."
	default:
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = "Sauvegardes planifiées et destination distincte/hors-site configurée."
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- Normalisation brut → BackupEvidence ---

// BackupWindowsNormalizer parse le JSON émis par PRDS1101WinCmd :
// {"solution_present":bool,"scheduled_job":bool,"offsite_configured":bool}.
func BackupWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		SolutionPresent   *bool `json:"solution_present"`
		ScheduledJob      *bool `json:"scheduled_job"`
		OffsiteConfigured *bool `json:"offsite_configured"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie sauvegarde illisible : %w", err)
	}
	if w.SolutionPresent == nil {
		return nil, errors.New("champ solution_present absent")
	}
	return json.Marshal(BackupEvidence{
		SolutionPresent:   derefBool(w.SolutionPresent),
		ScheduledJob:      derefBool(w.ScheduledJob),
		OffsiteConfigured: derefBool(w.OffsiteConfigured),
	})
}

// BackupLinuxNormalizer parse 3 lignes "yes"/"no" émises par PRDS1101LinuxCmd :
// présence d'un outil de sauvegarde, existence d'une planification, indice
// hors-site.
func BackupLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie sauvegarde vide")
	}
	ev := BackupEvidence{SolutionPresent: ls[0] == "yes"}
	if len(ls) > 1 {
		ev.ScheduledJob = ls[1] == "yes"
	}
	if len(ls) > 2 {
		ev.OffsiteConfigured = ls[2] == "yes"
	}
	return json.Marshal(ev)
}
