package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Famille PLATEFORME DE GESTION DES VULNÉRABILITÉS — contrôles Essential (non-KM)
// qui partagent une même sonde de DÉTECTION D'AGENT (VulnScannerEvidence). Sur le
// modèle de DE.CM-03-1 (détection d'un EDR par ses services), on constate en lecture
// seule la PRÉSENCE d'un scanner/agent de vulnérabilités connu en cours d'exécution
// (Tenable/Nessus, Qualys, Rapid7/ir_agent, OpenVAS/GVM). C'est un fait vérifiable ;
// mais la DISSÉMINATION des résultats, la REDDITION DE COMPTES sur la remédiation et
// le PROGRAMME de tests spécialisés restent des processus organisationnels que le scan
// ne peut pas observer depuis un hôte isolé. Ces contrôles sont donc MIXTES et
// PLAFONNENT à Defined (3) : au-delà, la preuve est organisationnelle (override tracé).

// VulnScannerEvidence = faits bruts (lecture seule) sur la présence d'un scanner /
// agent de gestion des vulnérabilités.
type VulnScannerEvidence struct {
	ScannerPresent bool   `json:"scanner_present"`
	ScannerName    string `json:"scanner_name,omitempty"`
}

// VulnScannerWinCmd (LECTURE SEULE) : liste les services dont le nom correspond à un
// scanner/agent de vulnérabilités connu et en cours d'exécution ; émet le JSON
// {scanner_present, scanner_name}.
const VulnScannerWinCmd = `$s=@(Get-Service 2>$null | Where-Object {$_.Name -match 'Tenable|Nessus|Qualys|ir_agent|Rapid7|GVM|openvas'} | Where-Object {$_.Status -eq 'Running'}); [pscustomobject]@{scanner_present=($s.Count -gt 0); scanner_name=(($s | Select-Object -First 1).Name)} | ConvertTo-Json`

// VulnScannerLinuxCmd (LECTURE SEULE) : teste les services d'agents de vulnérabilités
// connus, puis, à défaut, la présence des binaires en ligne de commande. Émet deux
// lignes : « yes »/« no » (présence) puis le nom de l'agent/outil trouvé (ou vide).
const VulnScannerLinuxCmd = `for s in nessusagent qualys-cloud-agent gvmd openvas ir_agent; do systemctl is-active $s 2>/dev/null | grep -q '^active' && { echo yes; echo $s; exit 0; }; done; command -v nessusd openvas gvmd 2>/dev/null | grep -q . && { echo yes; echo cli; exit 0; }; echo no; echo ''`

// decodeVulnScanner factorise le décodage commun aux évaluateurs de la famille : gère
// la collecte échouée et la preuve illisible via errorAssessment (renvoyé si non nil).
func decodeVulnScanner(raw assess.RawEvidence) (VulnScannerEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return VulnScannerEvidence{}, &ha
	}
	var ev VulnScannerEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return VulnScannerEvidence{}, &ha
	}
	return ev, nil
}

// evalScanner note la présence d'un scanner de vulnérabilités, plafonnée à Defined.
// Fonction PURE. label préfixe les messages pour identifier le contrôle. Le message de
// succès rappelle que la dissémination/reddition de comptes et le programme de tests
// restent organisationnels (à attester au questionnaire).
func evalScanner(host assess.HostRef, ev VulnScannerEvidence, label string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"scanner_present": ev.ScannerPresent,
		"scanner_name":    ev.ScannerName,
	}}
	var lvl cyfun.MaturityLevel
	if !ev.ScannerPresent {
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("%s : aucun scanner de vulnérabilités détecté.", label)
	} else {
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("%s : scanner détecté : %s ; la dissémination/reddition de comptes et le programme de tests restent organisationnels (à attester).", label, ev.ScannerName)
	}
	// Plafond : contrôle MIXTE, les processus organisationnels (dissémination, reddition
	// de comptes, programme de tests) ne peuvent être prouvés par le seul scan → jamais
	// au-dessus de Defined.
	if lvl > cyfun.Defined {
		lvl = cyfun.Defined
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- ID.RA-08.2 (Essential, non-KM, MIXTE) — plateforme de gestion/suivi des vulnérabilités ---
// Le scan constate la PRÉSENCE d'une plateforme/agent de gestion des vulnérabilités ;
// la dissémination et le suivi automatisés des remédiations restent organisationnels.

var IDRA0802Meta = cyfun.ControlMeta{
	ID: "ID.RA-08.2", Function: cyfun.Identify, Category: "ID.RA", Subcategory: "ID.RA-08",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall implement automated mechanisms for disseminating and tracking remedial measures related to vulnerability information that automatically handles vulnerability data collection, disseminates information, tracks remedial measures, includes reporting and accountability, and enables continuous monitoring.",
}

var IDRA0802Questions = []survey.Question{
	survey.Ask("ID.RA-08.2", survey.Documentation, "policy",
		"Une plateforme de gestion/suivi des vulnérabilités (collecte, dissémination, suivi des remédiations, reddition de comptes) est-elle documentée et exploitée ?"),
}

// VulnPlatform0802Evaluator (ID.RA-08.2) — MIXTE, plafond Defined.
type VulnPlatform0802Evaluator struct{}

func (VulnPlatform0802Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeVulnScanner(raw)
	if errHA != nil {
		return *errHA
	}
	return evalScanner(raw.Host, ev, "Plateforme de gestion des vulnérabilités")
}

// --- ID.IM-03.9 (Essential, non-KM, MIXTE) — scans de vulnérabilités réalisés ---
// Le scan constate la PRÉSENCE d'un outil de scan de vulnérabilités (trace d'outil) ;
// le programme de tests spécialisés (in-depth monitoring, malicious user testing, etc.)
// reste organisationnel.

var IDIM0309Meta = cyfun.ControlMeta{
	ID: "ID.IM-03.9", Function: cyfun.Identify, Category: "ID.IM", Subcategory: "ID.IM-03",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall conduct specialised assessments including in-depth monitoring, vulnerability scanning, malicious user testing, insider threat assessment, performance/load testing, and verification and validation testing on the organisation's critical systems.",
}

var IDIM0309Questions = []survey.Question{
	survey.Ask("ID.IM-03.9", survey.Documentation, "policy",
		"Un programme d'évaluations spécialisées (scans de vulnérabilités, tests d'intrusion, etc.) est-il documenté et exécuté périodiquement ?"),
}

// VulnAssessment0309Evaluator (ID.IM-03.9) — MIXTE, plafond Defined.
type VulnAssessment0309Evaluator struct{}

func (VulnAssessment0309Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeVulnScanner(raw)
	if errHA != nil {
		return *errHA
	}
	return evalScanner(raw.Host, ev, "Scans de vulnérabilités")
}

// --- Normalisation brut → VulnScannerEvidence ---

// VulnScannerWindowsNormalizer parse le JSON émis côté Windows :
// {"scanner_present":bool,"scanner_name":string}.
func VulnScannerWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		ScannerPresent *bool  `json:"scanner_present"`
		ScannerName    string `json:"scanner_name"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie scanner de vulnérabilités illisible : %w", err)
	}
	if w.ScannerPresent == nil {
		return nil, errors.New("champ scanner_present absent")
	}
	return json.Marshal(VulnScannerEvidence{
		ScannerPresent: derefBool(w.ScannerPresent),
		ScannerName:    w.ScannerName,
	})
}

// VulnScannerLinuxNormalizer parse la sortie côté Linux : ligne[0]=="yes" indique un
// scanner présent, ligne[1] (optionnelle) porte son nom. « no » seul est valide
// (scanner absent) ; une sortie vide est une erreur.
func VulnScannerLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie scanner de vulnérabilités vide")
	}
	ev := VulnScannerEvidence{ScannerPresent: ls[0] == "yes"}
	if ev.ScannerPresent && len(ls) > 1 {
		ev.ScannerName = ls[1]
	}
	return json.Marshal(ev)
}
