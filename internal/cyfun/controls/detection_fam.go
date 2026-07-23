package controls

import (
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// Famille DÉTECTION/RÉPONSE — contrôles MIXTES qui RÉUTILISENT la sonde
// EndpointMonitor (EndpointMonitorEvidence : présence d'un outil de détection
// endpoint/EDR, déjà écrite pour DE.CM-03-1 au niveau Basic). C'est le modèle
// « sonde de famille » : une seule collecte (présence d'un agent) alimente
// plusieurs contrôles à des niveaux différents. Ici la présence d'un outil est
// un FAIT scannable, mais la RÉPONSE opérationnelle (atténuation, investigation,
// évaluation d'impact) est un processus ORGANISATIONNEL que le scan ne peut pas
// observer depuis un hôte isolé. Ces contrôles plafonnent donc à Defined(3) :
// au-delà, la preuve est organisationnelle (override consultant tracé).

// decodeEndpointMonitor est défini dans endpoint_fam.go (même paquet) et réutilisé
// ici : une seule sonde EndpointMonitor, plusieurs familles la consomment.

// evalEndpointDetect note la présence d'un outil de détection, plafonnée à
// Defined (partie RÉPONSE/analyse organisationnelle). Fonction PURE.
// presentMsg reçoit le nom de l'agent (%s) ; absentMsg est fixe.
func evalEndpointDetect(host assess.HostRef, ev EndpointMonitorEvidence, presentMsg, absentMsg string) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"agent_present": ev.AgentPresent,
			"agent_name":    ev.AgentName,
		},
	}
	var lvl cyfun.MaturityLevel
	if !ev.AgentPresent {
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = absentMsg
	} else {
		// PLAFOND Defined(3) : la présence de l'outil est constatée, mais la
		// réponse/analyse opérationnelle reste à attester (organisationnel).
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf(presentMsg, ev.AgentName)
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- RS.MI-01.2 (Important, KEY MEASURE, MIXTE) — détection/atténuation aux
// frontières et points clés. Le scan constate la PRÉSENCE d'un dispositif de
// détection ; l'ATTÉNUATION en réponse reste organisationnelle → plafond Defined.

// RSMI0102Meta : texte officiel du CCB (Important, Key Measure).
var RSMI0102Meta = cyfun.ControlMeta{
	ID: "RS.MI-01.2", Function: cyfun.Respond, Category: "RS.MI", Subcategory: "RS.MI-01",
	Level: cyfun.LevelImportant, KeyMeasure: true,
	Requirement: "The organisation shall detect unauthorised access or data leakage and take appropriate mitigation actions, including monitoring of critical systems at external boundaries and key internal points.",
}

// RSMI0102Questions : volet Documentation (le scan couvre la présence de
// l'outil ; l'atténuation en réponse reste déclarative).
var RSMI0102Questions = []survey.Question{
	survey.Ask("RS.MI-01.2", survey.Documentation, "policy",
		"La détection des accès non autorisés / fuites de données et les actions d'atténuation associées (frontières externes, points internes clés) sont-elles documentées et exploitées par une procédure ?"),
}

// BoundaryDetect0102Evaluator (RS.MI-01.2) — MIXTE, plafond Defined.
type BoundaryDetect0102Evaluator struct{}

func (BoundaryDetect0102Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeEndpointMonitor(raw)
	if errHA != nil {
		return *errHA
	}
	return evalEndpointDetect(raw.Host, ev,
		"Outil de détection présent : %s ; l'atténuation en réponse reste à attester.",
		"Aucun dispositif de détection/atténuation détecté aux frontières/points clés.")
}

// --- RS.MA-02.2 (Essential, non-KM, MIXTE) — outillage d'investigation/forensic
// déployé. Le scan constate la PRÉSENCE d'un outil ; l'INVESTIGATION et
// l'évaluation d'impact restent organisationnelles → plafond Defined.

// RSMA0202Meta : texte officiel du CCB (Essential, non Key Measure).
var RSMA0202Meta = cyfun.ControlMeta{
	ID: "RS.MA-02.2", Function: cyfun.Respond, Category: "RS.MA", Subcategory: "RS.MA-02",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "Automated tools shall be used to support the investigation and impact assessment of validated cybersecurity incidents.",
}

// RSMA0202Questions : volet Documentation (le scan couvre la présence de
// l'outil ; son exploitation en investigation reste déclarative).
var RSMA0202Questions = []survey.Question{
	survey.Ask("RS.MA-02.2", survey.Documentation, "policy",
		"L'usage d'outils automatisés d'investigation/forensic pour l'analyse et l'évaluation d'impact des incidents est-il documenté et exploité par une procédure ?"),
}

// Forensic0202Evaluator (RS.MA-02.2) — MIXTE, plafond Defined.
type Forensic0202Evaluator struct{}

func (Forensic0202Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeEndpointMonitor(raw)
	if errHA != nil {
		return *errHA
	}
	return evalEndpointDetect(raw.Host, ev,
		"Outillage d'investigation/forensic présent : %s ; l'analyse/évaluation d'impact reste à attester.",
		"Aucun outillage d'investigation/forensic déployé n'a été détecté.")
}
