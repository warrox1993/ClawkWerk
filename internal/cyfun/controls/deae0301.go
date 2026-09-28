package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// DE.AE-03.1 — « The logging functionality of protection and detection tools
// shall be enabled. Logs shall be backed up and kept for a predefined period,
// and regularly reviewed to identify unusual or potentially harmful activity. »
// KEY MEASURE. Contrôle PARTIELLEMENT scannable : on constate sur l'hôte que la
// journalisation des OUTILS de protection/détection est bien ACTIVE (audit de
// sécurité + journalisation du pare-feu). En revanche, la rétention (durée de
// conservation, sauvegarde) et la revue régulière des journaux sont des
// pratiques ORGANISATIONNELLES, non observables par un scan hôte. Le scan
// plafonne donc HONNÊTEMENT à Defined (3) : le message rappelle toujours que la
// rétention/revue reste à attester par preuve organisationnelle (override tracé).

// DetLoggingEvidence = faits bruts (lecture seule) sur l'activation de la
// journalisation des outils de protection/détection.
type DetLoggingEvidence struct {
	SecurityAuditEnabled   bool `json:"security_audit_enabled"`   // audit de sécurité (logon/compte) actif
	FirewallLoggingEnabled bool `json:"firewall_logging_enabled"` // journalisation du pare-feu active
}

// DEAE0301Meta : texte officiel du CCB. Key Measure.
var DEAE0301Meta = cyfun.ControlMeta{
	ID:          "DE.AE-03.1",
	Function:    cyfun.Detect,
	Category:    "DE.AE",
	Subcategory: "DE.AE-03",
	Requirement: "The logging functionality of protection and detection tools shall be enabled. Logs shall be backed up and kept for a predefined period, and regularly reviewed to identify unusual or potentially harmful activity.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// DEAE0301Questions : volet Documentation. La rétention/sauvegarde/revue des
// journaux (partie non scannable du requirement) s'atteste ici.
var DEAE0301Questions = []survey.Question{
	survey.Ask("DE.AE-03.1", survey.Documentation, "policy",
		"La conservation, la sauvegarde et la revue régulière des journaux des outils de sécurité sont-elles cadrées par une procédure ?"),
}

// Commandes de collecte LECTURE SEULE. Isolées en constantes pour audit.

// DEAE0301WinCmd : auditpol (catégories logon/compte) + netsh advfirewall
// (journalisation des profils). Downlevel-friendly (Win7+), sortie JSON.
// Sources NEUTRES en langue (au lieu de parser auditpol/netsh dont la sortie est
// traduite) : journal Sécurité activé via Get-WinEvent (booléen), journalisation
// pare-feu via la valeur de REGISTRE (LogDroppedPackets = 0x1). Codes/hex neutres.
const DEAE0301WinCmd = `$sec=(Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue).IsEnabled; $fw=(reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging" /v LogDroppedPackets 2>$null | Select-String '0x1'); [pscustomobject]@{security_audit_enabled=[bool]$sec; firewall_logging_enabled=($fw -ne $null)} | ConvertTo-Json`

// DEAE0301LinuxCmd : deux lignes yes/no — auditd actif ; rsyslog OU
// systemd-journald actif.
const DEAE0301LinuxCmd = `systemctl is-active auditd 2>/dev/null | grep -q '^active' && echo yes || echo no; systemctl is-active rsyslog systemd-journald 2>/dev/null | grep -q '^active' && echo yes || echo no`

// DetLoggingEvaluator implémente assess.Evaluator pour DE.AE-03.1.
type DetLoggingEvaluator struct{}

func (DetLoggingEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev DetLoggingEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateDetLogging(raw.Host, ev)
}

// evaluateDetLogging : règle de décision pure. Plafond HONNÊTE à Defined(3) —
// la rétention et la revue régulière restent organisationnelles, jamais
// déduites du scan.
func evaluateDetLogging(host assess.HostRef, ev DetLoggingEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"security_audit_enabled":   ev.SecurityAuditEnabled,
			"firewall_logging_enabled": ev.FirewallLoggingEnabled,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case !ev.SecurityAuditEnabled && !ev.FirewallLoggingEnabled:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Journalisation des outils de protection désactivée ; rétention/revue à attester (preuve organisationnelle)."
	case ev.SecurityAuditEnabled && ev.FirewallLoggingEnabled:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = "Journalisation des outils de protection activée ; rétention/revue à attester (preuve organisationnelle)."
	default:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = "Journalisation des outils de protection partielle (un seul mécanisme actif) ; rétention/revue à attester (preuve organisationnelle)."
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- Normalisation brut → DetLoggingEvidence ---

// DetLoggingWindowsNormalizer parse le JSON émis par DEAE0301WinCmd :
// {"security_audit_enabled":bool,"firewall_logging_enabled":bool}.
func DetLoggingWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		SecurityAuditEnabled   *bool `json:"security_audit_enabled"`
		FirewallLoggingEnabled *bool `json:"firewall_logging_enabled"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie journalisation outils illisible : %w", err)
	}
	if w.SecurityAuditEnabled == nil {
		return nil, errors.New("champ security_audit_enabled absent")
	}
	return json.Marshal(DetLoggingEvidence{
		SecurityAuditEnabled:   derefBool(w.SecurityAuditEnabled),
		FirewallLoggingEnabled: derefBool(w.FirewallLoggingEnabled),
	})
}

// DetLoggingLinuxNormalizer parse 2 lignes yes/no émises par DEAE0301LinuxCmd :
// ligne[0] = audit (auditd) actif ; ligne[1] = journal (rsyslog/journald) actif.
func DetLoggingLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie journalisation outils vide")
	}
	ev := DetLoggingEvidence{SecurityAuditEnabled: ls[0] == "yes"}
	if len(ls) > 1 {
		ev.FirewallLoggingEnabled = ls[1] == "yes"
	}
	return json.Marshal(ev)
}
