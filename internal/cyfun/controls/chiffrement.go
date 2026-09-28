package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Famille CHIFFREMENT — protection de la confidentialité des données par
// chiffrement, constatée sur l'hôte (lecture seule). Une seule sonde
// EncryptionEvidence alimente trois contrôles Essential de la sous-catégorie
// PR.DS à des niveaux/plafonds différents :
//   - PR.DS-01.6 : confidentialité AU REPOS (chiffrement du volume système).
//   - PR.DS-02.2 : confidentialité EN TRANSIT (signature/chiffrement SMB imposé).
//   - PR.DS-02.1 : contrôle des supports amovibles (KEY MEASURE, MIXTE).
//
// Modèle « sonde de famille » (cf. durcissement.go) : le scan constate l'état
// technique, mais le PROCESSUS organisationnel (politique de chiffrement,
// device-control) reste attesté au questionnaire (axe Documentation). Les deux
// contrôles SCAN purs plafonnent à Managed ; le contrôle MIXTE PR.DS-02.1
// plafonne à Defined — la maîtrise organisationnelle du parc amovible ne se
// prouve pas depuis un seul hôte.

// EncryptionEvidence = faits bruts (lecture seule) sur l'état du chiffrement.
type EncryptionEvidence struct {
	AtRestEnabled      bool `json:"at_rest_enabled"`     // volume système chiffré (BitLocker / dm-crypt)
	InTransitEnforced  bool `json:"in_transit_enforced"` // signature/chiffrement des flux imposé (SMB)
	RemovableEncrypted bool `json:"removable_encrypted"` // supports amovibles chiffrés
	// InTransitUnknown : aucun service de partage à signer n'est présent (Linux
	// sans Samba) ; l'absence de smb.conf n'est pas « des flux exposés ».
	InTransitUnknown bool `json:"in_transit_unknown,omitempty"`
	// RemovableUnknown : aucune obligation de chiffrement des supports
	// amovibles n'est constatable (Linux) ; jamais lu comme « non chiffrés ».
	RemovableUnknown bool `json:"removable_unknown,omitempty"`
}

// EncryptionWinCmd : collecte Windows LECTURE SEULE, émet du JSON
// {at_rest_enabled, in_transit_enforced, removable_encrypted}. Lit l'état
// BitLocker du volume système, l'exigence de signature du client SMB, et la
// présence d'au moins un volume de données amovible protégé.
const EncryptionWinCmd = WinPre + `$os=$null; $osd=$null; try{$v=Get-BitLockerVolume -MountPoint $env:SystemDrive -EA Stop; $os=("$($v.ProtectionStatus)" -eq 'On')}catch [Management.Automation.CommandNotFoundException]{$os=$null}catch{if("$($_.Exception.GetType().FullName) $($_.Exception.Message)" -match 'UnauthorizedAccess|0x80070005|denied|refus|autoris|verweigert|geweigerd'){$osd='BitLocker (Win32_EncryptableVolume, reserve aux administrateurs)'}else{F 'BitLocker' $_}}; try{$smb=[bool](Get-SmbClientConfiguration -EA Stop).RequireSecuritySignature}catch{try{$smb=((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -EA Stop).RequireSecuritySignature -eq 1)}catch{F 'signature SMB (LanmanWorkstation)' $_}}; $fve=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE -EA SilentlyContinue; [pscustomobject]@{at_rest_enabled=$os; at_rest_denied=$osd; in_transit_enforced=$smb; removable_encrypted=($fve.RDVDenyWriteAccess -eq 1)}|ConvertTo-Json`

// EncryptionLinuxCmd : collecte Linux LECTURE SEULE, émet 3 lignes yes/no :
// chiffrement au repos (présence d'un device de type crypt), en transit
// best-effort (signature Samba configurée), média amovible (best-effort : non).
const EncryptionLinuxCmd = `S=$(findmnt -no SOURCE / 2>/dev/null); if [ -n "$S" ]; then lsblk -sno TYPE "$S" 2>/dev/null | grep -q crypt && echo yes || echo no; else lsblk -o TYPE 2>/dev/null | grep -q crypt && echo yes || echo no; fi; (if [ -f /etc/samba/smb.conf ]; then grep -qsiE '^[[:space:]]*(server signing|client signing|smb encrypt)[[:space:]]*=[[:space:]]*(mandatory|required)' /etc/samba/smb.conf && echo yes || echo no; else echo unknown; fi); echo unknown`

// decodeEncryption factorise le décodage commun aux évaluateurs de la famille :
// gère la collecte échouée et la preuve illisible via errorAssessment (renvoyé
// si non nil).
func decodeEncryption(raw assess.RawEvidence) (EncryptionEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return EncryptionEvidence{}, &ha
	}
	var ev EncryptionEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return EncryptionEvidence{}, &ha
	}
	return ev, nil
}

// evalEncryptionFlag note un unique fait booléen de chiffrement, plafonné à cap.
// Fonction PURE : enabled true => (passLvl, Pass, passMsg) ; false => (failLvl,
// failStatus, failMsg). detailKey nomme le fait exposé dans le Finding.
func evalEncryptionFlag(host assess.HostRef, enabled bool, detailKey string,
	passLvl, failLvl cyfun.MaturityLevel, failStatus assess.Status,
	cap cyfun.MaturityLevel, passMsg, failMsg string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{detailKey: enabled}}
	var lvl cyfun.MaturityLevel
	if enabled {
		lvl, f.Status, f.Message = passLvl, assess.StatusPass, passMsg
	} else {
		lvl, f.Status, f.Message = failLvl, failStatus, failMsg
	}
	if lvl > cap { // plafond : le scan seul ne prouve pas la maturité organisationnelle.
		lvl = cap
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- PR.DS-01.6 (Essential) — confidentialité au repos (SCAN pur) ---

// PRDS0106Meta : texte officiel du CCB (Essential).
var PRDS0106Meta = cyfun.ControlMeta{
	ID: "PR.DS-01.6", Function: cyfun.Protect, Category: "PR.DS", Subcategory: "PR.DS-01",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall protect the confidentiality of its critical assets while at rest.",
}

// PRDS0106Questions : volet Documentation (le scan couvre l'Implementation).
var PRDS0106Questions = []survey.Question{
	survey.Ask("PR.DS-01.6", survey.Documentation, "policy",
		"Le chiffrement des données au repos (disques, volumes) est-il documenté, approuvé et revu ?"),
}

// AtRestEncryptionEvaluator (PR.DS-01.6) — SCAN pur, plafond Managed.
type AtRestEncryptionEvaluator struct{}

func (AtRestEncryptionEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeEncryption(raw)
	if errHA != nil {
		return *errHA
	}
	return evalEncryptionFlag(raw.Host, ev.AtRestEnabled, "at_rest_enabled",
		cyfun.Managed, cyfun.Initial, assess.StatusFail, cyfun.Managed,
		"Volume système chiffré : confidentialité au repos assurée.",
		"Volume système non chiffré : données au repos exposées.")
}

// --- PR.DS-02.2 (Essential) — confidentialité en transit (SCAN pur) ---

var PRDS0202Meta = cyfun.ControlMeta{
	ID: "PR.DS-02.2", Function: cyfun.Protect, Category: "PR.DS", Subcategory: "PR.DS-02",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall protect its critical and sensitive information while in transit.",
}

var PRDS0202Questions = []survey.Question{
	survey.Ask("PR.DS-02.2", survey.Documentation, "policy",
		"Le chiffrement/la signature des données en transit (SMB, protocoles réseau) est-il documenté, approuvé et revu ?"),
}

// InTransitEncryptionEvaluator (PR.DS-02.2) — SCAN pur, plafond Managed.
type InTransitEncryptionEvaluator struct{}

func (InTransitEncryptionEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeEncryption(raw)
	if errHA != nil {
		return *errHA
	}
	if ev.InTransitUnknown {
		return errorAssessment(raw.Host, "Chiffrement en transit : aucun service de partage de fichiers (Samba) sur cet hôte, rien à constater côté hôte — à attester au questionnaire.")
	}
	return evalEncryptionFlag(raw.Host, ev.InTransitEnforced, "in_transit_enforced",
		cyfun.Managed, cyfun.Initial, assess.StatusFail, cyfun.Managed,
		"Signature/chiffrement des flux imposé : confidentialité en transit assurée.",
		"Signature/chiffrement des flux non imposé : données en transit exposées.")
}

// --- PR.DS-02.1 (Essential, KEY MEASURE, MIXTE) — supports amovibles ---
// Le scan constate si les supports amovibles sont chiffrés, mais le
// device-control organisationnel (politique, inventaire, transport) reste
// attesté au questionnaire → plafond Defined.

var PRDS0201Meta = cyfun.ControlMeta{
	ID: "PR.DS-02.1", Function: cyfun.Protect, Category: "PR.DS", Subcategory: "PR.DS-02",
	Level: cyfun.LevelEssential, KeyMeasure: true,
	Requirement: "Portable storage devices containing system data shall be controlled and protected while in transit and in storage.",
}

var PRDS0201Questions = []survey.Question{
	survey.Ask("PR.DS-02.1", survey.Documentation, "policy",
		"Le contrôle et la protection des supports amovibles (chiffrement, inventaire, transport) sont-ils documentés, approuvés et revus ?"),
}

// RemovableEncryptionEvaluator (PR.DS-02.1) — MIXTE, KEY MEASURE, plafond Defined.
type RemovableEncryptionEvaluator struct{}

func (RemovableEncryptionEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeEncryption(raw)
	if errHA != nil {
		return *errHA
	}
	if ev.RemovableUnknown {
		return errorAssessment(raw.Host, "Chiffrement des supports amovibles : aucune obligation technique constatable sur cet hôte — à attester au questionnaire.")
	}
	return evalEncryptionFlag(raw.Host, ev.RemovableEncrypted, "removable_encrypted",
		cyfun.Defined, cyfun.Repeatable, assess.StatusPartial, cyfun.Defined,
		"Chiffrement des supports amovibles imposé par stratégie (BitLocker To Go) ; device-control organisationnel à attester.",
		"Aucune obligation technique de chiffrer les supports amovibles (device-control organisationnel à attester).")
}

// --- Normalisation brut → EncryptionEvidence ---

// EncryptionWindowsNormalizer parse le JSON émis côté Windows :
// {"at_rest_enabled":bool,"in_transit_enforced":bool,"removable_encrypted":bool}.
func EncryptionWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	ev, _, err := encryptionWindows(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(ev)
}

// EncryptionWindowsNormalizerFor spécialise le normaliseur par contrôle : l'état
// BitLocker est réservé aux administrateurs, mais la signature SMB et la
// stratégie BitLocker To Go se lisent sans droits. Seul PR.DS-01.6 (au repos)
// dépend de BitLocker : les deux autres contrôles restent évalués.
func EncryptionWindowsNormalizerFor(axis string) assess.NormalizeFunc {
	return func(raw []byte) (json.RawMessage, error) {
		ev, w, err := encryptionWindows(raw)
		if err != nil {
			return nil, err
		}
		if axis == "at_rest" {
			if w.AtRestDenied != nil && *w.AtRestDenied != "" {
				return nil, fmt.Errorf("droits insuffisants : lecture refusée (%s)", *w.AtRestDenied)
			}
			if w.AtRestEnabled == nil {
				return nil, errors.New("état BitLocker indisponible (module absent ou chiffrement tiers) : chiffrement au repos à attester")
			}
		}
		if axis == "in_transit" && w.InTransitEnforced == nil {
			return nil, errors.New("champ in_transit_enforced absent")
		}
		return json.Marshal(ev)
	}
}

type encryptionWinRaw struct {
	AtRestEnabled      *bool   `json:"at_rest_enabled"`
	AtRestDenied       *string `json:"at_rest_denied"`
	InTransitEnforced  *bool   `json:"in_transit_enforced"`
	RemovableEncrypted *bool   `json:"removable_encrypted"`
}

func encryptionWindows(raw []byte) (EncryptionEvidence, encryptionWinRaw, error) {
	var w encryptionWinRaw
	if err := json.Unmarshal(raw, &w); err != nil {
		return EncryptionEvidence{}, w, fmt.Errorf("sortie chiffrement illisible : %w", err)
	}
	if w.AtRestEnabled == nil && w.AtRestDenied == nil && w.InTransitEnforced == nil {
		return EncryptionEvidence{}, w, errors.New("champs de chiffrement absents")
	}
	return EncryptionEvidence{
		AtRestEnabled:      derefBool(w.AtRestEnabled),
		InTransitEnforced:  derefBool(w.InTransitEnforced),
		RemovableEncrypted: derefBool(w.RemovableEncrypted),
	}, w, nil
}

// EncryptionLinuxNormalizer parse 3 lignes yes/no : chiffrement au repos,
// en transit, supports amovibles (dans cet ordre).
func EncryptionLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie chiffrement vide")
	}
	yes := func(i int) bool { return i < len(ls) && ls[i] == "yes" }
	return json.Marshal(EncryptionEvidence{
		AtRestEnabled:      yes(0),
		InTransitEnforced:  yes(1),
		RemovableEncrypted: yes(2),
		InTransitUnknown:   len(ls) < 2 || (ls[1] != "yes" && ls[1] != "no"),
		RemovableUnknown:   len(ls) < 3 || (ls[2] != "yes" && ls[2] != "no"),
	})
}
