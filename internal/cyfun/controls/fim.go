package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Famille INTÉGRITÉ / FIM (File Integrity Monitoring) — la sonde constate, en
// lecture seule, la présence d'un outil de contrôle d'intégrité sur l'hôte
// (Tripwire, OSSEC, Wazuh, Sysmon, AIDE, Qualys, Tanium…). Une seule collecte
// FimEvidence alimente deux contrôles Essential de la sous-catégorie PR.DS-01 :
//   - PR.DS-01.2 : un outil de vérification d'intégrité EST présent.
//   - PR.DS-01.3 : une RÉPONSE AUTOMATISÉE aux violations est en place.
//
// Modèle « sonde de famille » (cf. durcissement.go / chiffrement.go) : ces deux
// contrôles sont MIXTES. Le scan prouve la PRÉSENCE technique de l'outil, mais
// la notification automatisée effective (PR.DS-01.2) et surtout la réponse
// automatisée proportionnée (PR.DS-01.3) relèvent d'un PROCESSUS organisationnel
// (règles, playbooks, seuils) attesté au questionnaire (axe Documentation).
// D'où le PLAFOND Defined : le scan seul ne prouve pas la maturité du processus.
// La détection de la réponse automatisée n'étant pas fiable à distance en
// lecture seule, auto_response est collecté à false et PR.DS-01.3 s'appuie sur
// la présence de l'outil comme prérequis, en laissant la réponse à attester.

// FimEvidence = faits bruts (lecture seule) sur l'outillage d'intégrité.
type FimEvidence struct {
	FimPresent   bool `json:"fim_present"`   // un outil de contrôle d'intégrité tourne sur l'hôte
	AutoResponse bool `json:"auto_response"` // réponse automatisée aux violations (non prouvable à distance : false)
}

// FimWinCmd : collecte Windows LECTURE SEULE. Énumère les services et repère un
// agent d'intégrité connu à l'état Running, émet du JSON {fim_present,
// auto_response}. auto_response reste false : la réponse automatisée n'est pas
// prouvable de façon fiable depuis un simple relevé de services.
const FimWinCmd = `$fim=@(Get-Service 2>$null | Where-Object {$_.Name -match 'Tripwire|OSSEC|Wazuh|Sysmon|AIDE|Qualys|Tanium'} | Where-Object {$_.Status -eq 'Running'}); [pscustomobject]@{fim_present=($fim.Count -gt 0); auto_response=$false} | ConvertTo-Json`

// FimLinuxCmd : collecte Linux LECTURE SEULE, émet 2 lignes yes/no : présence
// d'un outil FIM (binaire installé ou agent actif), puis réponse automatisée
// (toujours no : non prouvable à distance).
const FimLinuxCmd = `(command -v aide tripwire ossec-syscheckd 2>/dev/null | grep -q . || systemctl is-active wazuh-agent ossec 2>/dev/null | grep -q '^active') && echo yes || echo no; echo no`

// decodeFim factorise le décodage commun aux évaluateurs de la famille : gère la
// collecte échouée et la preuve illisible via errorAssessment (renvoyé si non nil).
func decodeFim(raw assess.RawEvidence) (FimEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return FimEvidence{}, &ha
	}
	var ev FimEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return FimEvidence{}, &ha
	}
	return ev, nil
}

// evalFimFlag note un unique fait booléen d'intégrité, plafonné à cap. Fonction
// PURE : present true => (passLvl, passStatus, passMsg) ; false => (Initial,
// Fail, failMsg). detailKey nomme le fait exposé dans le Finding.
func evalFimFlag(host assess.HostRef, present bool, detailKey string,
	passLvl cyfun.MaturityLevel, passStatus assess.Status,
	cap cyfun.MaturityLevel, passMsg, failMsg string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{detailKey: present}}
	var lvl cyfun.MaturityLevel
	if present {
		lvl, f.Status, f.Message = passLvl, passStatus, passMsg
	} else {
		lvl, f.Status, f.Message = cyfun.Initial, assess.StatusFail, failMsg
	}
	if lvl > cap { // plafond : le scan seul ne prouve pas la maturité organisationnelle.
		lvl = cap
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- PR.DS-01.2 (Essential, MIXTE) — outil de contrôle d'intégrité présent ---
// Le scan constate qu'un outil FIM tourne ; la notification automatisée
// effective et sa gouvernance restent attestées au questionnaire → plafond Defined.

// PRDS0102Meta : texte officiel du CCB (Essential).
var PRDS0102Meta = cyfun.ControlMeta{
	ID: "PR.DS-01.2", Function: cyfun.Protect, Category: "PR.DS", Subcategory: "PR.DS-01",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall implement automated tools where feasible to provide notification upon discovering discrepancies during integrity verification.",
}

// PRDS0102Questions : volet Documentation (le scan couvre l'Implementation).
var PRDS0102Questions = []survey.Question{
	survey.Ask("PR.DS-01.2", survey.Documentation, "policy",
		"L'usage d'un outil de contrôle d'intégrité (FIM) et la notification des écarts sont-ils documentés, approuvés et revus ?"),
}

// Fim0102Evaluator (PR.DS-01.2) — MIXTE, plafond Defined.
type Fim0102Evaluator struct{}

func (Fim0102Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeFim(raw)
	if errHA != nil {
		return *errHA
	}
	return evalFimFlag(raw.Host, ev.FimPresent, "fim_present",
		cyfun.Defined, assess.StatusPass, cyfun.Defined,
		"Outil de contrôle d'intégrité (FIM) détecté (gouvernance des notifications à attester).",
		"Aucun outil de contrôle d'intégrité (FIM) détecté.")
}

// --- PR.DS-01.3 (Essential, MIXTE) — réponse automatisée aux violations ---
// La réponse automatisée n'est pas prouvable à distance en lecture seule : le
// scan utilise la présence de l'outil FIM comme PRÉREQUIS. Présent => la
// capacité existe mais la réponse automatisée reste à attester (Partial,
// plafond Defined) ; absent => prérequis manquant (Initial/Fail).

var PRDS0103Meta = cyfun.ControlMeta{
	ID: "PR.DS-01.3", Function: cyfun.Protect, Category: "PR.DS", Subcategory: "PR.DS-01",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall define and implement automated responses to detected integrity violations, using predefined safeguards that are proportionate to the severity and impact of the violation.",
}

var PRDS0103Questions = []survey.Question{
	survey.Ask("PR.DS-01.3", survey.Documentation, "policy",
		"Les réponses automatisées aux violations d'intégrité (garde-fous proportionnés) sont-elles définies, documentées, approuvées et revues ?"),
}

// Fim0103Evaluator (PR.DS-01.3) — MIXTE, plafond Defined. La présence de l'outil
// FIM sert de prérequis ; la réponse automatisée effective reste à attester.
type Fim0103Evaluator struct{}

func (Fim0103Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeFim(raw)
	if errHA != nil {
		return *errHA
	}
	return evalFimFlag(raw.Host, ev.FimPresent, "fim_present",
		cyfun.Defined, assess.StatusPartial, cyfun.Defined,
		"FIM présent ; la réponse automatisée reste à attester.",
		"Aucun outil de contrôle d'intégrité : réponse automatisée aux violations impossible.")
}

// --- Normalisation brut → FimEvidence ---

// FimWindowsNormalizer parse le JSON émis côté Windows :
// {"fim_present":bool,"auto_response":bool}. fim_present est requis.
func FimWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		FimPresent   *bool `json:"fim_present"`
		AutoResponse *bool `json:"auto_response"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie FIM illisible : %w", err)
	}
	if w.FimPresent == nil {
		return nil, errors.New("champ fim_present absent")
	}
	return json.Marshal(FimEvidence{
		FimPresent:   derefBool(w.FimPresent),
		AutoResponse: derefBool(w.AutoResponse),
	})
}

// FimLinuxNormalizer parse 2 lignes yes/no : présence FIM, réponse automatisée
// (dans cet ordre). Une sortie vide est une erreur (pas de preuve exploitable).
func FimLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie FIM vide")
	}
	yes := func(i int) bool { return i < len(ls) && ls[i] == "yes" }
	return json.Marshal(FimEvidence{
		FimPresent:   yes(0),
		AutoResponse: yes(1),
	})
}
