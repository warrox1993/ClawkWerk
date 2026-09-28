package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Famille CONTRÔLE APPLICATIF / ALLOWLISTING. Une seule sonde (AppControlEvidence :
// un allowlisting deny-all est-il actif, et via quel moteur) alimente plusieurs
// contrôles à des niveaux différents. C'est le même modèle « sonde de famille » que
// durcissement.go : une collecte, plusieurs contrôles, seuils et PLAFOND adaptés.
//
// Le fait TECHNIQUE observable est binaire : un mécanisme d'allowlisting « deny-all,
// permit-by-exception » est-il en vigueur sur l'hôte (AppLocker/WDAC côté Windows,
// SELinux/AppArmor en mode enforce côté Linux) ? Le contrôle Essential PR.PS-01.4
// est un SCAN pur de cette exigence et plafonne à Managed. Les contrôles Important
// PR.PS-02.1 / PR.PS-05.2 sont MIXTES : le scan constate l'existence du garde-fou
// technique, mais la GOUVERNANCE du cycle logiciel (règles d'usage/installation,
// maintien/retrait selon le risque) reste organisationnelle → plafond Defined,
// preuve au questionnaire.

// AppControlEvidence = faits bruts (lecture seule) sur l'allowlisting applicatif.
type AppControlEvidence struct {
	AllowlistingActive bool   `json:"allowlisting_active"`
	Mode               string `json:"mode,omitempty"` // "applocker" | "wdac" | "selinux" | "apparmor" | "none"
}

// AppControlWinCmd : collecte Windows LECTURE SEULE. Considère l'allowlisting actif
// si une politique AppLocker effective a au moins une RuleCollection, OU si Device
// Guard rapporte l'intégrité du code en mode audit/enforce (WDAC). Émet du JSON
// {allowlisting_active, mode}.
const AppControlWinCmd = WinPre + `try{$al=@(Get-AppLockerPolicy -Effective -EA Stop|Select-Object -ExpandProperty RuleCollections|?{$_.Count -gt 0 -and "$($_.EnforcementMode)" -eq 'Enabled'})}catch{F 'AppLocker' $_}; $dg=$null; try{$dg=(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -EA Stop).UsermodeCodeIntegrityPolicyEnforcementStatus}catch{if($al.Count -eq 0){F 'Device Guard (WMI)' $_}}; $active=(($al.Count -gt 0) -or ($dg -ge 2)); $mode=if($dg -ge 2){'wdac'}elseif($al.Count -gt 0){'applocker'}else{'none'}; [pscustomobject]@{allowlisting_active=$active; mode=$mode}|ConvertTo-Json`

// AppControlLinuxCmd : collecte Linux LECTURE SEULE, émet 2 lignes : "yes"/"no"
// (un MAC est-il en mode enforce), puis le moteur détecté (selinux/apparmor/none).
const AppControlLinuxCmd = `(getenforce 2>/dev/null | grep -qi enforcing || aa-status 2>/dev/null | grep -q 'profiles are in enforce mode') && echo yes || echo no; (getenforce 2>/dev/null | grep -qi enforcing && echo selinux || (aa-status >/dev/null 2>&1 && echo apparmor || echo none))`

// --- Normalisation brut → AppControlEvidence ---

// AppControlWindowsNormalizer parse le JSON émis côté Windows :
// {"allowlisting_active":bool,"mode":string}. allowlisting_active est requis.
func AppControlWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		AllowlistingActive *bool  `json:"allowlisting_active"`
		Mode               string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie contrôle applicatif illisible : %w", err)
	}
	if w.AllowlistingActive == nil {
		return nil, errors.New("champ allowlisting_active absent")
	}
	return json.Marshal(AppControlEvidence{
		AllowlistingActive: derefBool(w.AllowlistingActive),
		Mode:               w.Mode,
	})
}

// AppControlLinuxNormalizer parse 2 lignes : "yes"/"no" (MAC en enforce) puis le
// moteur détecté. Une sortie vide est une erreur (preuve inexploitable).
func AppControlLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie contrôle applicatif vide")
	}
	ev := AppControlEvidence{AllowlistingActive: ls[0] == "yes"}
	if len(ls) > 1 {
		ev.Mode = ls[1]
	}
	return json.Marshal(ev)
}

// decodeAppControl factorise le décodage commun aux évaluateurs de la famille :
// gère la collecte échouée et la preuve illisible via errorAssessment (non nil).
func decodeAppControl(raw assess.RawEvidence) (AppControlEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return AppControlEvidence{}, &ha
	}
	var ev AppControlEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return AppControlEvidence{}, &ha
	}
	return ev, nil
}

// evalAppControl note l'allowlisting à partir d'une preuve AppControl. Fonction PURE.
// activeLvl/inactiveLvl = niveaux proposés selon que l'allowlisting est actif ou non ;
// activeStatus/inactiveStatus = statut du constat associé ; cap = plafond de niveau
// (un contrôle MIXTE ne dépasse pas Defined par scan seul). activeMsg reçoit le mode
// détecté en argument.
func evalAppControl(host assess.HostRef, ev AppControlEvidence,
	activeLvl cyfun.MaturityLevel, activeStatus assess.Status,
	inactiveLvl cyfun.MaturityLevel, inactiveStatus assess.Status,
	cap cyfun.MaturityLevel, activeMsg, inactiveMsg string) assess.HostAssessment {

	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"allowlisting_active": ev.AllowlistingActive,
		"mode":                ev.Mode,
	}}
	var lvl cyfun.MaturityLevel
	if ev.AllowlistingActive {
		lvl, f.Status = activeLvl, activeStatus
		mode := ev.Mode
		if mode == "" {
			mode = "moteur non identifié"
		}
		f.Message = fmt.Sprintf("%s (moteur : %s).", activeMsg, mode)
	} else {
		lvl, f.Status = inactiveLvl, inactiveStatus
		f.Message = inactiveMsg
	}
	if lvl > cap { // plafond de niveau : le 5/5 (et le MIXTE > Defined) s'atteste hors scan.
		lvl = cap
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- PR.PS-01.4 (Essential, non-KM, SCAN pur) — allowlisting deny-all ---

// PRPS0104Meta : texte officiel du CCB (Essential).
var PRPS0104Meta = cyfun.ControlMeta{
	ID: "PR.PS-01.4", Function: cyfun.Protect, Category: "PR.PS", Subcategory: "PR.PS-01",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall implement technical safeguards to enforce a policy of ‘deny-all’ and ‘permit-by-exception’ so that only authorised software programmes are executed.",
}

// PRPS0104Questions : volet Documentation (le scan couvre l'Implementation).
var PRPS0104Questions = []survey.Question{
	survey.Ask("PR.PS-01.4", survey.Documentation, "policy",
		"Une politique d'allowlisting « deny-all, permit-by-exception » est-elle documentée, approuvée et revue ?"),
}

// AllowlistingEvaluator (PR.PS-01.4) — SCAN pur, plafond Managed.
type AllowlistingEvaluator struct{}

func (AllowlistingEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeAppControl(raw)
	if errHA != nil {
		return *errHA
	}
	return evalAppControl(raw.Host, ev,
		cyfun.Managed, assess.StatusPass,
		cyfun.Initial, assess.StatusFail,
		cyfun.Managed,
		"Allowlisting deny-all actif : seuls les logiciels autorisés s'exécutent",
		"Aucun allowlisting deny-all détecté : l'exécution de logiciels non autorisés n'est pas empêchée.")
}

// --- PR.PS-02.1 (Important, non-KM, MIXTE) — restrictions d'usage/installation ---
// Le scan constate le garde-fou technique (AppLocker/WDAC/MAC) ; le maintien/retrait
// des logiciels selon le risque reste organisationnel → plafond Defined.

var PRPS0201Meta = cyfun.ControlMeta{
	ID: "PR.PS-02.1", Function: cyfun.Protect, Category: "PR.PS", Subcategory: "PR.PS-02",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "The organisation shall enforce restrictions on software usage and installation, and ensure that software is maintained, replaced, or removed based on its associated risk.",
}

var PRPS0201Questions = []survey.Question{
	survey.Ask("PR.PS-02.1", survey.Documentation, "policy",
		"Les restrictions d'usage et d'installation de logiciels, et leur maintien/retrait selon le risque, sont-ils documentés et revus ?"),
}

// SoftwareRestrictionEvaluator (PR.PS-02.1) — MIXTE, plafond Defined.
type SoftwareRestrictionEvaluator struct{}

func (SoftwareRestrictionEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeAppControl(raw)
	if errHA != nil {
		return *errHA
	}
	return evalAppControl(raw.Host, ev,
		cyfun.Defined, assess.StatusPartial,
		cyfun.Repeatable, assess.StatusFail,
		cyfun.Defined,
		"Restriction technique d'exécution observée : gouvernance du cycle logiciel à attester",
		"Aucune restriction technique d'installation/exécution détectée sur l'hôte.")
}

// --- PR.PS-05.2 (Important, non-KM, MIXTE) — empêcher l'exécution non autorisée ---
// Même sonde/logique que PR.PS-02.1 : garde-fou technique constaté, gouvernance à
// attester → plafond Defined.

var PRPS0502Meta = cyfun.ControlMeta{
	ID: "PR.PS-05.2", Function: cyfun.Protect, Category: "PR.PS", Subcategory: "PR.PS-05",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "Installation and execution of unauthorised software shall be prevented.",
}

var PRPS0502Questions = []survey.Question{
	survey.Ask("PR.PS-05.2", survey.Documentation, "policy",
		"L'interdiction d'installer et d'exécuter des logiciels non autorisés est-elle documentée, approuvée et revue ?"),
}

// UnauthorisedSoftwareEvaluator (PR.PS-05.2) — MIXTE, plafond Defined.
type UnauthorisedSoftwareEvaluator struct{}

func (UnauthorisedSoftwareEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeAppControl(raw)
	if errHA != nil {
		return *errHA
	}
	return evalAppControl(raw.Host, ev,
		cyfun.Defined, assess.StatusPartial,
		cyfun.Repeatable, assess.StatusFail,
		cyfun.Defined,
		"Exécution de logiciels non autorisés empêchée techniquement : gouvernance du cycle logiciel à attester",
		"Rien n'empêche techniquement l'installation/exécution de logiciels non autorisés.")
}
