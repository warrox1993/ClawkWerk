package controls

import (
	"encoding/json"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// Famille GESTION DES VULNÉRABILITÉS — contrôles Important (non-KM) qui RÉUTILISENT
// la sonde de patching (PatchEvidence, déjà écrite pour ID.AM-08.2). C'est le même
// modèle « sonde de famille » que DURCISSEMENT : une seule collecte alimente plusieurs
// contrôles. Ici les contrôles sont MIXTES : le scan constate l'ÉTAT (correctifs de
// sécurité en attente par hôte), mais le PROCESSUS continu de gestion des vulnérabilités
// (surveillance, documentation, remédiation) reste organisationnel → PLAFOND Defined,
// avec un message qui rappelle que ce processus reste à attester au questionnaire.
//
// NB : on réutilise UNIQUEMENT le type PatchEvidence et un décodage JSON simple ; on
// n'appelle PAS le normaliseur Linux (qui exige une horloge injectée). L'évaluateur
// reste donc pur et trivialement testable.

// Seuil « nombreux correctifs » : au-delà, le parc est en retard manifeste.
const vulnManyPending = 10

// decodePatch factorise le décodage commun aux évaluateurs de la famille : gère la
// collecte échouée et la preuve illisible via errorAssessment (renvoyé si non nil).
func decodePatch(raw assess.RawEvidence) (PatchEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return PatchEvidence{}, &ha
	}
	var ev PatchEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return PatchEvidence{}, &ha
	}
	return ev, nil
}

// evalVuln note l'état des vulnérabilités connues à partir des correctifs de sécurité
// en attente, plafonné à Defined (processus de gestion des vulnérabilités à attester).
// Fonction PURE. label préfixe les messages pour identifier le contrôle.
func evalVuln(host assess.HostRef, ev PatchEvidence, label string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"pending_security_updates": ev.PendingSecurityUpdates,
		"days_since_last_update":   ev.DaysSinceLastUpdate,
		"manager":                  ev.Manager,
	}}
	var lvl cyfun.MaturityLevel
	switch {
	case ev.PendingSecurityUpdates > vulnManyPending:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("%s : nombreux correctifs de sécurité en attente (%d).", label, ev.PendingSecurityUpdates)
	case ev.PendingSecurityUpdates > 0:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("%s : %d correctif(s) de sécurité en attente.", label, ev.PendingSecurityUpdates)
	default:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("%s : aucun correctif de sécurité en attente ; le processus de gestion des vulnérabilités reste à attester.", label)
	}
	// Plafond : contrôle MIXTE, le processus continu de gestion des vulnérabilités
	// (organisationnel) ne peut être prouvé par le seul scan → jamais au-dessus de Defined.
	if lvl > cyfun.Defined {
		lvl = cyfun.Defined
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- ID.RA-01.2 (Important, non-KM, MIXTE) — composants/logiciels obsolètes ---
// Le scan constate les correctifs de sécurité manquants (proxy d'obsolescence des
// composants) ; l'identification/documentation continue reste organisationnelle.

var IDRA0102Meta = cyfun.ControlMeta{
	ID: "ID.RA-01.2", Function: cyfun.Identify, Category: "ID.RA", Subcategory: "ID.RA-01",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "A process shall be established to continuously monitor, identify, and document vulnerabilities of the organisation's business critical systems.",
}

var IDRA0102Questions = []survey.Question{
	survey.Ask("ID.RA-01.2", survey.Documentation, "policy",
		"Le processus d'identification et de documentation des composants/logiciels obsolètes est-il documenté et revu ?"),
}

// Vuln0102Evaluator (ID.RA-01.2) — MIXTE, plafond Defined.
type Vuln0102Evaluator struct{}

func (Vuln0102Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodePatch(raw)
	if errHA != nil {
		return *errHA
	}
	return evalVuln(raw.Host, ev, "Composants obsolètes")
}

// --- ID.RA-01.6 (Important, non-KM, MIXTE) — vulnérabilités connues corrigées ---
// Le scan constate les correctifs manquants par hôte ; la gestion continue des
// vulnérabilités sur l'ensemble des actifs reste organisationnelle.

var IDRA0106Meta = cyfun.ControlMeta{
	ID: "ID.RA-01.6", Function: cyfun.Identify, Category: "ID.RA", Subcategory: "ID.RA-01",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "Vulnerabilities shall be identified and managed in all relevant assets, including software, network and system architectures, and facilities.",
}

var IDRA0106Questions = []survey.Question{
	survey.Ask("ID.RA-01.6", survey.Documentation, "policy",
		"La correction des vulnérabilités connues (application des correctifs manquants) est-elle documentée et revue ?"),
}

// Vuln0106Evaluator (ID.RA-01.6) — MIXTE, plafond Defined.
type Vuln0106Evaluator struct{}

func (Vuln0106Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodePatch(raw)
	if errHA != nil {
		return *errHA
	}
	return evalVuln(raw.Host, ev, "Vulnérabilités connues")
}
