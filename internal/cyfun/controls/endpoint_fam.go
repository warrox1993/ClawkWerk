package controls

import (
	"encoding/json"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Famille ENDPOINT-DÉTECTION — incrément suivant : réutilisation de la sonde
// EndpointMonitorEvidence (agent EDR/détection présent + nom), déjà écrite pour
// DE.CM-03-1 (Basic). Même modèle « sonde de famille » que DURCISSEMENT : une
// seule collecte alimente plusieurs contrôles à des niveaux CyFun différents.
//
// Ces deux contrôles sont MIXTES : le scan constate en lecture seule la
// PRÉSENCE d'un outil de détection endpoint (fait vérifiable), mais
// l'EXPLOITATION réelle — analyse comportementale, corrélation SOC, tuning des
// règles, tri des alertes vs faux positifs — est un processus organisationnel
// que le scan ne peut pas observer depuis un hôte isolé. D'où le PLAFOND
// Defined(3) : au-delà, la preuve est organisationnelle (override tracé).

// decodeEndpointMonitor factorise le décodage commun aux évaluateurs de la
// famille : gère la collecte échouée et la preuve illisible via errorAssessment
// (déjà défini dans decm0102.go). Renvoie un pointeur non nil à court-circuiter.
func decodeEndpointMonitor(raw assess.RawEvidence) (EndpointMonitorEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return EndpointMonitorEvidence{}, &ha
	}
	var ev EndpointMonitorEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return EndpointMonitorEvidence{}, &ha
	}
	return ev, nil
}

// evalEndpointDetection : règle de décision PURE, partagée par la famille.
// !AgentPresent → Initial/Fail ; AgentPresent → Defined/Pass. Toujours plafonnée
// à cap (Defined pour ces contrôles MIXTES). label distingue le contrôle dans
// le message. Note : `cap` shadow le builtin homonyme, comme dans durcissement.go.
func evalEndpointDetection(host assess.HostRef, ev EndpointMonitorEvidence, cap cyfun.MaturityLevel, label string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"agent_present": ev.AgentPresent,
		"agent_name":    ev.AgentName,
	}}
	var lvl cyfun.MaturityLevel
	if !ev.AgentPresent {
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("%s : aucun outil de détection endpoint détecté.", label)
	} else {
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("%s : outil détecté : %s ; exploitation/analyse et tuning à attester.", label, ev.AgentName)
	}
	if lvl > cap { // plafond : l'analyse comportementale/SOC reste organisationnelle.
		lvl = cap
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- DE.CM-03.2 (Important, non-KM, MIXTE) — outils de détection endpoint/réseau gérés ---

// DECM0302Meta : texte officiel du CCB (Important). Non Key Measure.
var DECM0302Meta = cyfun.ControlMeta{
	ID:          "DE.CM-03.2",
	Function:    cyfun.Detect,
	Category:    "DE.CM",
	Subcategory: "DE.CM-03",
	Level:       cyfun.LevelImportant,
	KeyMeasure:  false,
	Requirement: "End point and network protection tools that monitor end-user behaviour for dangerous activity shall be managed.",
}

// DECM0302Questions : volet Documentation (le scan couvre la présence de
// l'outil ; sa GESTION par une procédure reste déclarative).
var DECM0302Questions = []survey.Question{
	survey.Ask("DE.CM-03.2", survey.Documentation, "policy",
		"Les outils de détection comportementale endpoint/réseau (EDR/IDPS) sont-ils gérés par une procédure documentée, approuvée et revue ?"),
}

// Edr0302Evaluator implémente assess.Evaluator pour DE.CM-03.2. Plafond Defined.
type Edr0302Evaluator struct{}

func (Edr0302Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeEndpointMonitor(raw)
	if errHA != nil {
		return *errHA
	}
	return evalEndpointDetection(raw.Host, ev, cyfun.Defined, "Détection comportementale endpoint/réseau")
}

// --- DE.CM-09.4 (Essential, non-KM, MIXTE) — anti-malware actif + gestion des alertes ---

// DECM0904Meta : texte officiel du CCB (Essential). Non Key Measure.
var DECM0904Meta = cyfun.ControlMeta{
	ID:          "DE.CM-09.4",
	Function:    cyfun.Detect,
	Category:    "DE.CM",
	Subcategory: "DE.CM-09",
	Level:       cyfun.LevelEssential,
	KeyMeasure:  false,
	Requirement: "The organisation shall establish a system to accurately distinguish between legitimate alerts and false positives, ensuring effective detection and removal of malicious code.",
}

// DECM0904Questions : volet Documentation (le scan couvre la présence de
// l'EDR/anti-malware actif ; le tri alertes/faux positifs reste déclaratif).
var DECM0904Questions = []survey.Question{
	survey.Ask("DE.CM-09.4", survey.Documentation, "policy",
		"Un système distinguant les alertes légitimes des faux positifs (tri, tuning, réponse) est-il documenté, approuvé et revu ?"),
}

// Edr0904Evaluator implémente assess.Evaluator pour DE.CM-09.4. Plafond Defined.
type Edr0904Evaluator struct{}

func (Edr0904Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeEndpointMonitor(raw)
	if errHA != nil {
		return *errHA
	}
	return evalEndpointDetection(raw.Host, ev, cyfun.Defined, "Anti-malware/EDR actif")
}
