package controls

import (
	"encoding/json"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// Famille DURCISSEMENT-CONFIG — incrément 1 : réduction de la surface d'exposition.
// Ces contrôles Important/Essential RÉUTILISENT la sonde Hardening (HardeningEvidence :
// protocoles legacy + ports en écoute), déjà écrite pour PR.AA-05.3 (Basic). C'est le
// modèle « sonde de famille » : une seule collecte alimente plusieurs contrôles à des
// niveaux différents, avec des seuils et un PLAFOND adaptés au niveau. Les contrôles
// Essential (SCAN purs) plafonnent à Managed ; le contrôle Important MIXTE (baseline
// documentée) plafonne à Defined — l'existence d'une baseline écrite reste au questionnaire.

// evalSurface note la réduction de surface à partir d'une preuve Hardening, plafonnée à
// cap. Fonction PURE. portsWide = seuil « surface large » ; portsOK = seuil « maîtrisée ».
func evalSurface(host assess.HostRef, ev HardeningEvidence, portsWide, portsOK int, cap cyfun.MaturityLevel, label string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"legacy_services":      ev.LegacyServices,
		"open_listening_ports": ev.OpenListeningPorts,
	}}
	var lvl cyfun.MaturityLevel
	switch {
	case ev.LegacyServices > 0:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("%s : %d protocole(s) legacy en clair détecté(s).", label, ev.LegacyServices)
	case ev.OpenListeningPorts > portsWide:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("%s : surface large (%d ports en écoute) à réduire.", label, ev.OpenListeningPorts)
	case ev.OpenListeningPorts > portsOK:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("%s : surface maîtrisée (%d ports en écoute).", label, ev.OpenListeningPorts)
	default:
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = fmt.Sprintf("%s : surface minimale (%d ports en écoute).", label, ev.OpenListeningPorts)
	}
	if lvl > cap { // plafond de niveau : un contrôle MIXTE ne dépasse pas Defined par scan seul.
		lvl = cap
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// decodeHardening factorise le décodage commun aux évaluateurs de la famille : gère la
// collecte échouée et la preuve illisible via errorAssessment (renvoyé si non nil).
func decodeHardening(raw assess.RawEvidence) (HardeningEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return HardeningEvidence{}, &ha
	}
	var ev HardeningEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return HardeningEvidence{}, &ha
	}
	return ev, nil
}

// --- PR.PS-01.3 (Essential) — désactiver ports/protocoles/services inutiles (SCAN pur) ---

// PRPS0103Meta : texte officiel du CCB (Essential).
var PRPS0103Meta = cyfun.ControlMeta{
	ID: "PR.PS-01.3", Function: cyfun.Protect, Category: "PR.PS", Subcategory: "PR.PS-01",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall identify and disable specific functions, ports, protocols, and services within its critical systems that are not required for business operations.",
}

// PRPS0103Questions : volet Documentation (le scan couvre l'Implementation).
var PRPS0103Questions = []survey.Question{
	survey.Ask("PR.PS-01.3", survey.Documentation, "policy",
		"L'identification et la désactivation des fonctions, ports, protocoles et services inutiles sont-elles documentées et revues ?"),
}

// PortHardeningEvaluator (PR.PS-01.3). Seuils Essential (plus stricts que Basic).
type PortHardeningEvaluator struct{}

func (PortHardeningEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeHardening(raw)
	if errHA != nil {
		return *errHA
	}
	return evalSurface(raw.Host, ev, 10, 3, cyfun.Managed, "Ports/services inutiles")
}

// --- PR.PS-01.2 (Essential) — n'opérer qu'avec les fonctions essentielles (SCAN pur) ---

var PRPS0102Meta = cyfun.ControlMeta{
	ID: "PR.PS-01.2", Function: cyfun.Protect, Category: "PR.PS", Subcategory: "PR.PS-01",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall configure its business-critical systems to operate with only the essential functions needed for the intended purpose. This includes reviewing and updating baseline configurations to disable any non-essential capabilities.",
}

var PRPS0102Questions = []survey.Question{
	survey.Ask("PR.PS-01.2", survey.Documentation, "policy",
		"La configuration des systèmes pour n'opérer qu'avec les fonctions essentielles est-elle documentée et revue ?"),
}

// EssentialFunctionsEvaluator (PR.PS-01.2).
type EssentialFunctionsEvaluator struct{}

func (EssentialFunctionsEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeHardening(raw)
	if errHA != nil {
		return *errHA
	}
	return evalSurface(raw.Host, ev, 10, 3, cyfun.Managed, "Fonctions non essentielles")
}

// --- PR.PS-01.1 (Important, KEY MEASURE, MIXTE) — baseline de configuration ---
// Le scan constate l'état DURCI (surface), mais l'existence d'une baseline
// DOCUMENTÉE et maintenue reste organisationnelle → plafond Defined.

var PRPS0101Meta = cyfun.ControlMeta{
	ID: "PR.PS-01.1", Function: cyfun.Protect, Category: "PR.PS", Subcategory: "PR.PS-01",
	Level: cyfun.LevelImportant, KeyMeasure: true,
	Requirement: "The organisation shall develop, document, and maintain a baseline configuration for its business-critical systems.",
}

var PRPS0101Questions = []survey.Question{
	survey.Ask("PR.PS-01.1", survey.Documentation, "policy",
		"Une baseline de configuration durcie est-elle développée, documentée, approuvée et maintenue ?"),
}

// BaselineHardeningEvaluator (PR.PS-01.1) — MIXTE, plafond Defined.
type BaselineHardeningEvaluator struct{}

func (BaselineHardeningEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeHardening(raw)
	if errHA != nil {
		return *errHA
	}
	return evalSurface(raw.Host, ev, 15, 5, cyfun.Defined, "Baseline : état durci observé (baseline documentée à attester)")
}
