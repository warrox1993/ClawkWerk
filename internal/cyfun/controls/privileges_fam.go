package controls

import (
	"encoding/json"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// Famille PRIVILÈGES — modèle « sonde de famille » appliqué aux comptes à
// privilèges. Ces contrôles Important/Essential RÉUTILISENT la sonde déjà
// écrite pour PR.AA-05.4 (LocalAdminEvidence : nombre d'admins locaux + compte
// intégré désactivé). Une seule collecte alimente plusieurs contrôles à des
// niveaux différents, avec des seuils adaptés au niveau.
//
// Ces contrôles sont MIXTES : le scan constate combien de comptes à privilèges
// existent (moindre privilège), mais l'exigence de les « surveiller » (05.7) et
// de les « auditer » (05.9) est une revue FORMELLE, organisationnelle, que le
// scan ne peut pas prouver. D'où un PLAFOND Defined(3) : la maîtrise du
// périmètre observée au scan ne suffit pas à décerner Managed/Optimizing, qui
// supposent une surveillance/audit continus attestés au questionnaire.

// decodeLocalAdmin factorise le décodage commun aux évaluateurs de la famille :
// gère la collecte échouée et la preuve illisible via errorAssessment (renvoyé
// si non nil). Miroir de decodeHardening pour la sonde LocalAdminEvidence.
func decodeLocalAdmin(raw assess.RawEvidence) (LocalAdminEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return LocalAdminEvidence{}, &ha
	}
	var ev LocalAdminEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return LocalAdminEvidence{}, &ha
	}
	return ev, nil
}

// Seuils stricts pour l'Essential (05.9) : plus exigeants que l'Important, qui
// réutilise adminsManyThreshold(5)/adminsToleratedThreshold(2) de PR.AA-05.4.
const (
	privAdminsManyStrict      = 3 // > 3 comptes à privilèges : dispersion (Essential)
	privAdminsToleratedStrict = 1 // ≤ 1 : périmètre à privilèges resserré (Essential)
)

// evalPrivAccounts note le périmètre des comptes à privilèges à partir d'une
// preuve LocalAdmin, plafonné à cap. Fonction PURE. many = seuil « trop de
// comptes » ; tolerated = seuil « périmètre maîtrisé ». label rappelle que la
// surveillance/revue formelle reste à attester (embarqué dans chaque message).
func evalPrivAccounts(host assess.HostRef, ev LocalAdminEvidence, many, tolerated int, cap cyfun.MaturityLevel, label string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"admin_count":            ev.AdminCount,
		"builtin_admin_disabled": ev.BuiltinAdminDisabled,
	}}
	var lvl cyfun.MaturityLevel
	switch {
	case ev.AdminCount > many:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("%s : trop de comptes à privilèges (%d) à limiter.", label, ev.AdminCount)
	case ev.AdminCount > tolerated:
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = fmt.Sprintf("%s : %d comptes à privilèges, à réduire au strict nécessaire.", label, ev.AdminCount)
	case !ev.BuiltinAdminDisabled:
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = fmt.Sprintf("%s : périmètre resserré (%d), mais compte intégré actif.", label, ev.AdminCount)
	default:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("%s : comptes à privilèges limités (%d), compte intégré désactivé.", label, ev.AdminCount)
	}
	if lvl > cap { // plafond : la surveillance/audit continu ne se prouve pas au scan.
		lvl = cap
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- PR.AA-05.7 (Important, non-KM, MIXTE) — comptes à privilèges gérés et surveillés ---

// PRAA0507Meta : texte officiel du CCB (Important).
var PRAA0507Meta = cyfun.ControlMeta{
	ID: "PR.AA-05.7", Function: cyfun.Protect, Category: "PR.AA", Subcategory: "PR.AA-05",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "Privileged users shall be managed and monitored.",
}

// PRAA0507Questions : volet Documentation (le scan couvre l'Implementation ;
// la surveillance formelle reste attestée ici).
var PRAA0507Questions = []survey.Question{
	survey.Ask("PR.AA-05.7", survey.Documentation, "policy",
		"La gestion et la surveillance des comptes à privilèges sont-elles documentées, approuvées et revues ?"),
}

// PrivAccounts0507Evaluator (PR.AA-05.7) — MIXTE, plafond Defined. Seuils
// Important (réutilise ceux de PR.AA-05.4).
type PrivAccounts0507Evaluator struct{}

func (PrivAccounts0507Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeLocalAdmin(raw)
	if errHA != nil {
		return *errHA
	}
	return evalPrivAccounts(raw.Host, ev, adminsManyThreshold, adminsToleratedThreshold, cyfun.Defined,
		"Comptes à privilèges (surveillance formelle à attester)")
}

// --- PR.AA-05.9 (Essential, non-KM, MIXTE) — comptes à privilèges gérés, surveillés ET audités ---

// PRAA0509Meta : texte officiel du CCB (Essential).
var PRAA0509Meta = cyfun.ControlMeta{
	ID: "PR.AA-05.9", Function: cyfun.Protect, Category: "PR.AA", Subcategory: "PR.AA-05",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "Privileged users shall be managed, monitored and audited.",
}

// PRAA0509Questions : volet Documentation. L'audit de l'usage des comptes à
// privilèges est organisationnel → attesté ici.
var PRAA0509Questions = []survey.Question{
	survey.Ask("PR.AA-05.9", survey.Documentation, "policy",
		"La gestion, la surveillance et l'audit de l'usage des comptes à privilèges dédiés sont-ils documentés, approuvés et revus ?"),
}

// PrivAccounts0509Evaluator (PR.AA-05.9) — MIXTE, plafond Defined. Seuils
// stricts (Essential exige des comptes à privilèges dédiés + audit).
type PrivAccounts0509Evaluator struct{}

func (PrivAccounts0509Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeLocalAdmin(raw)
	if errHA != nil {
		return *errHA
	}
	return evalPrivAccounts(raw.Host, ev, privAdminsManyStrict, privAdminsToleratedStrict, cyfun.Defined,
		"Comptes à privilèges (surveillance/audit formels à attester)")
}
