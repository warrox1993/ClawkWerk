package controls

import (
	"encoding/json"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Famille BACKUP — incrément Important. Ces contrôles RÉUTILISENT la sonde de
// sauvegarde déjà écrite pour PR.DS-11.1 (Basic) : une seule collecte
// (BackupEvidence : solution présente, tâche planifiée, hors-site) alimente
// plusieurs contrôles. C'est le modèle « sonde de famille » (cf. durcissement.go).
//
// PR.DS-11.2 et PR.DS-11.3 sont des contrôles Important MIXTES : le scan
// constate la POSTURE technique (une solution existe, planifiée, avec une
// destination distincte), mais le cœur de l'exigence — le TEST de restauration
// effectivement réalisé (11.2) et l'ÉQUIVALENCE des contrôles de sécurité du
// stockage de sauvegarde (11.3) — reste organisationnel et non prouvable en
// lecture seule depuis l'hôte. D'où un PLAFOND à Defined(3) : le 4/5 et le 5/5
// s'attestent par preuve documentaire via override tracé, jamais par scan seul.

// backupCap est le plafond de niveau de la famille : le scan ne prouve pas le
// test de restauration ni l'équivalence des contrôles → jamais au-delà de Defined.
const backupCap = cyfun.Defined

// decodeBackup factorise le décodage commun aux évaluateurs de la famille : gère
// la collecte échouée et la preuve illisible via errorAssessment (défini dans
// decm0102.go). Renvoie un pointeur non nil sur l'assessment d'erreur à
// retourner tel quel, ou (evidence, nil) si tout va bien.
func decodeBackup(raw assess.RawEvidence) (BackupEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return BackupEvidence{}, &ha
	}
	var ev BackupEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return BackupEvidence{}, &ha
	}
	return ev, nil
}

// backupAssessment construit l'HostAssessment commun (findings + niveau plafonné).
func backupAssessment(host assess.HostRef, ev BackupEvidence, lvl cyfun.MaturityLevel, status assess.Status, msg string) assess.HostAssessment {
	if lvl > backupCap { // plafond : un contrôle MIXTE ne dépasse pas Defined par scan seul.
		lvl = backupCap
	}
	f := assess.Finding{
		HostID: host.ID,
		Status: status,
		Detail: map[string]any{
			"solution_present":   ev.SolutionPresent,
			"scheduled_job":      ev.ScheduledJob,
			"offsite_configured": ev.OffsiteConfigured,
		},
		Message: msg,
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         msg,
	}
}

// --- PR.DS-11.2 (Important, MIXTE) — les sauvegardes sont testées régulièrement ---
// Le scan constate qu'une sauvegarde planifiée existe, mais le TEST de
// restauration effectif reste à attester → plafond Defined.

// PRDS1102Meta : texte officiel du CCB (Important, non-KM).
var PRDS1102Meta = cyfun.ControlMeta{
	ID:          "PR.DS-11.2",
	Function:    cyfun.Protect,
	Category:    "PR.DS",
	Subcategory: "PR.DS-11",
	Requirement: "The reliability and integrity of backups shall be verified and tested regularly.",
	Level:       cyfun.LevelImportant,
	KeyMeasure:  false,
}

// PRDS1102Questions : volet Documentation (le scan couvre l'Implementation).
var PRDS1102Questions = []survey.Question{
	survey.Ask("PR.DS-11.2", survey.Documentation, "policy",
		"La vérification et le test réguliers de la fiabilité et de l'intégrité des sauvegardes sont-ils documentés et réalisés (test de restauration à attester) ?"),
}

// BackupTested1102Evaluator (PR.DS-11.2) — MIXTE, plafond Defined.
type BackupTested1102Evaluator struct{}

func (BackupTested1102Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeBackup(raw)
	if errHA != nil {
		return *errHA
	}
	switch {
	case !ev.SolutionPresent:
		return backupAssessment(raw.Host, ev, cyfun.Initial, assess.StatusFail,
			"Aucune solution de sauvegarde détectée : rien à tester.")
	case !ev.ScheduledJob:
		return backupAssessment(raw.Host, ev, cyfun.Repeatable, assess.StatusPartial,
			"Solution présente mais aucune sauvegarde planifiée ; test de restauration à attester.")
	default:
		return backupAssessment(raw.Host, ev, cyfun.Defined, assess.StatusPartial,
			"Sauvegardes planifiées : présence constatée ; le TEST de restauration reste à attester.")
	}
}

// --- PR.DS-11.3 (Important, MIXTE) — sauvegardes sur un emplacement distinct/hors-site ---
// Le scan constate un indice d'emplacement distinct, mais l'ÉQUIVALENCE des
// contrôles de sécurité du stockage de sauvegarde reste à attester → plafond Defined.

// PRDS1103Meta : texte officiel du CCB (Important, non-KM).
var PRDS1103Meta = cyfun.ControlMeta{
	ID:          "PR.DS-11.3",
	Function:    cyfun.Protect,
	Category:    "PR.DS",
	Subcategory: "PR.DS-11",
	Requirement: "The organisation shall maintain secure backups of business-critical data in a separate storage location to ensure data availability in case of system failure or data loss. Backup storage shall apply equivalent security controls as the primary environment.",
	Level:       cyfun.LevelImportant,
	KeyMeasure:  false,
}

// PRDS1103Questions : volet Documentation (le scan couvre l'Implementation).
var PRDS1103Questions = []survey.Question{
	survey.Ask("PR.DS-11.3", survey.Documentation, "policy",
		"Le stockage des sauvegardes sur un emplacement distinct/hors-site appliquant des contrôles de sécurité équivalents est-il documenté (équivalence à attester) ?"),
}

// BackupOffsite1103Evaluator (PR.DS-11.3) — MIXTE, plafond Defined.
type BackupOffsite1103Evaluator struct{}

func (BackupOffsite1103Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeBackup(raw)
	if errHA != nil {
		return *errHA
	}
	if ev.OffsiteConfigured {
		return backupAssessment(raw.Host, ev, cyfun.Defined, assess.StatusPass,
			"Emplacement distinct/hors-site configuré ; l'équivalence des contrôles de sécurité reste à attester.")
	}
	return backupAssessment(raw.Host, ev, cyfun.Repeatable, assess.StatusPartial,
		"Emplacement distinct/hors-site non confirmé ; à attester au questionnaire.")
}
