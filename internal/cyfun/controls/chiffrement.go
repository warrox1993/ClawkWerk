package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
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
}

// EncryptionWinCmd : collecte Windows LECTURE SEULE, émet du JSON
// {at_rest_enabled, in_transit_enforced, removable_encrypted}. Lit l'état
// BitLocker du volume système, l'exigence de signature du client SMB, et la
// présence d'au moins un volume de données amovible protégé.
const EncryptionWinCmd = `$os=(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue).ProtectionStatus; $smb=(Get-SmbClientConfiguration -ErrorAction SilentlyContinue).RequireSecuritySignature; $rem=@(Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object {$_.VolumeType -eq 'Data' -and $_.ProtectionStatus -eq 'On'}).Count; [pscustomobject]@{at_rest_enabled=($os -eq 'On'); in_transit_enforced=[bool]$smb; removable_encrypted=($rem -gt 0)} | ConvertTo-Json`

// EncryptionLinuxCmd : collecte Linux LECTURE SEULE, émet 3 lignes yes/no :
// chiffrement au repos (présence d'un device de type crypt), en transit
// best-effort (signature Samba configurée), média amovible (best-effort : non).
const EncryptionLinuxCmd = `lsblk -o TYPE 2>/dev/null | grep -q crypt && echo yes || echo no; (grep -qs -E 'server signing|client signing' /etc/samba/smb.conf 2>/dev/null && echo yes || echo no); echo no`

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
	return evalEncryptionFlag(raw.Host, ev.RemovableEncrypted, "removable_encrypted",
		cyfun.Defined, cyfun.Repeatable, assess.StatusPartial, cyfun.Defined,
		"Supports amovibles chiffrés observés (device-control organisationnel à attester).",
		"Aucun support amovible chiffré observé (device-control organisationnel à attester).")
}

// --- Normalisation brut → EncryptionEvidence ---

// EncryptionWindowsNormalizer parse le JSON émis côté Windows :
// {"at_rest_enabled":bool,"in_transit_enforced":bool,"removable_encrypted":bool}.
func EncryptionWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		AtRestEnabled      *bool `json:"at_rest_enabled"`
		InTransitEnforced  *bool `json:"in_transit_enforced"`
		RemovableEncrypted *bool `json:"removable_encrypted"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie chiffrement illisible : %w", err)
	}
	if w.AtRestEnabled == nil {
		return nil, errors.New("champ at_rest_enabled absent")
	}
	return json.Marshal(EncryptionEvidence{
		AtRestEnabled:      derefBool(w.AtRestEnabled),
		InTransitEnforced:  derefBool(w.InTransitEnforced),
		RemovableEncrypted: derefBool(w.RemovableEncrypted),
	})
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
	})
}
