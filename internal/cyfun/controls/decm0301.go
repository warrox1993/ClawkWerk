package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// DE.CM-03-1 — « End point and network protection tools to monitor end-user
// behaviour for dangerous activity shall be implemented. » NON Key Measure.
// Contrôle SCANNABLE : on constate sur l'hôte la PRÉSENCE d'un outil de
// surveillance endpoint/EDR (agent/service connu en cours d'exécution). C'est
// un fait vérifiable en lecture seule ; mais l'EXPLOITATION réelle (analyse
// comportementale, corrélation SOC, réponse) est un processus organisationnel
// que le scan ne peut pas observer depuis un hôte isolé. Le scan plafonne donc
// à Defined (3) : au-delà, la preuve est organisationnelle (override tracé).
//
// NB : l'ID « DE.CM-03-1 » contient un TIRET (et non un point) — c'est la
// forme officielle du fichier CCB, reproduite telle quelle.

// EndpointMonitorEvidence = faits bruts (lecture seule) sur la présence d'un
// outil de surveillance endpoint/EDR.
type EndpointMonitorEvidence struct {
	AgentPresent bool   `json:"agent_present"`
	AgentName    string `json:"agent_name,omitempty"`
}

// DECM0301Meta : texte officiel du CCB. Non Key Measure.
var DECM0301Meta = cyfun.ControlMeta{
	ID:          "DE.CM-03-1",
	Function:    cyfun.Detect,
	Category:    "DE.CM",
	Subcategory: "DE.CM-03",
	Requirement: "End point and network protection tools to monitor end-user behaviour for dangerous activity shall be implemented.",
	Level:       "Basic",
	KeyMeasure:  false,
}

// DECM0301Questions : volet Documentation (le scan couvre la présence de
// l'outil ; l'exploitation par une procédure reste déclarative).
var DECM0301Questions = []survey.Question{
	survey.Ask("DE.CM-03-1", survey.Documentation, "policy",
		"L'usage d'outils de détection comportementale endpoint/réseau (EDR/IDPS) est-il prévu et exploité par une procédure ?"),
}

// DECM0301WinCmd (LECTURE SEULE) : liste les services dont le nom correspond à
// un agent EDR connu et en cours d'exécution, et émet {agent_present, agent_name}.
const DECM0301WinCmd = `$e=@(Get-Service 2>$null | Where-Object {$_.Name -match 'Sense|CSFalconService|SentinelAgent|CbDefense|xagt|ESET|SepMasterService|WdNisSvc'} | Where-Object {$_.Status -eq 'Running'}); [pscustomobject]@{agent_present=($e.Count -gt 0); agent_name=(($e | Select-Object -First 1).Name)} | ConvertTo-Json`

// DECM0301LinuxCmd (LECTURE SEULE) : teste les services EDR connus ; émet
// deux lignes (yes/no puis le nom de l'agent si trouvé).
const DECM0301LinuxCmd = `for s in falcon-sensor sentinelone ds_agent xagt osqueryd wazuh-agent; do systemctl is-active $s 2>/dev/null | grep -q '^active' && { echo yes; echo $s; exit 0; }; done; echo no; echo ''`

// EndpointMonitorEvaluator implémente assess.Evaluator pour DE.CM-03-1.
type EndpointMonitorEvaluator struct{}

func (EndpointMonitorEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev EndpointMonitorEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateEndpointMonitor(raw.Host, ev)
}

// evaluateEndpointMonitor : règle de décision pure. PLAFOND Defined(3) — au-delà,
// l'exploitation/analyse comportementale relève de l'organisationnel.
func evaluateEndpointMonitor(host assess.HostRef, ev EndpointMonitorEvidence) assess.HostAssessment {
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
		f.Message = "Aucun outil de surveillance endpoint/EDR détecté."
	} else {
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("Outil de surveillance endpoint détecté : %s ; exploitation/analyse comportementale à attester.", ev.AgentName)
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- Normalisation brut → EndpointMonitorEvidence ---

// EndpointMonitorWindowsNormalizer parse le JSON émis côté Windows :
// {"agent_present":bool,"agent_name":string}.
func EndpointMonitorWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		AgentPresent *bool  `json:"agent_present"`
		AgentName    string `json:"agent_name"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie surveillance endpoint illisible : %w", err)
	}
	if w.AgentPresent == nil {
		return nil, errors.New("champ agent_present absent")
	}
	return json.Marshal(EndpointMonitorEvidence{
		AgentPresent: derefBool(w.AgentPresent),
		AgentName:    w.AgentName,
	})
}

// EndpointMonitorLinuxNormalizer parse la sortie côté Linux : ligne[0]=="yes"
// indique un agent présent, ligne[1] (optionnelle) porte son nom. « no » seul
// est valide (agent absent) ; une sortie vide est une erreur.
func EndpointMonitorLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie surveillance endpoint vide")
	}
	ev := EndpointMonitorEvidence{AgentPresent: ls[0] == "yes"}
	if ev.AgentPresent && len(ls) > 1 {
		ev.AgentName = ls[1]
	}
	return json.Marshal(ev)
}
