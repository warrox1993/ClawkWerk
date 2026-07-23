package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// Famille JOURNALISATION / SIEM — modèle « sonde de famille » : UNE seule collecte
// (LogMgmtEvidence) alimente plusieurs contrôles Important/Essential. Le scan constate
// la PRÉSENCE de dispositifs techniques (audit activé, transfert de logs, agent SIEM),
// mais la RÉTENTION, la REVUE et l'ANALYSE effectives des journaux restent des preuves
// d'ordre organisationnel. Tous ces contrôles sont donc MIXTES et plafonnent à Defined (3) :
// le scan atteste l'implémentation technique, pas la maturité du processus, laquelle
// s'atteste par preuve documentaire (via le questionnaire, override tracé pour aller au-delà).

// LogMgmtEvidence = faits bruts (lecture seule) sur la journalisation de l'hôte.
type LogMgmtEvidence struct {
	AuditEnabled  bool `json:"audit_enabled"`  // audit/journalisation système activé
	LogForwarding bool `json:"log_forwarding"` // transfert des journaux vers un système alternatif
	SiemPresent   bool `json:"siem_present"`   // agent de collecte/analyse (SIEM) présent et actif
}

// LogMgmtWinCmd : collecte Windows LECTURE SEULE. Vérifie l'audit (auditpol),
// le transfert d'événements (WEF SubscriptionManager) et la présence d'un agent
// SIEM/collecteur en service. Émet du JSON {audit_enabled, log_forwarding, siem_present}.
// audit_enabled via Get-WinEvent (journal Sécurité activé, booléen NEUTRE) au lieu
// de parser auditpol (traduit). log_forwarding : la donnée de registre "Server=..."
// est une chaîne de config neutre. SIEM : noms de services (invariants).
const LogMgmtWinCmd = `$sec=(Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue).IsEnabled; $fwd=(reg query "HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" 2>$null | Select-String 'Server'); $siem=@(Get-Service 2>$null | Where-Object {$_.Name -match 'splunk|Wazuh|nxlog|Sysmon|MMAExtension|AzureMonitorAgent'} | Where-Object {$_.Status -eq 'Running'}); [pscustomobject]@{audit_enabled=[bool]$sec; log_forwarding=($fwd -ne $null); siem_present=($siem.Count -gt 0)} | ConvertTo-Json`

// LogMgmtLinuxCmd : collecte Linux LECTURE SEULE, émet 3 lignes yes/no :
// audit/journalisation actif ; transfert rsyslog distant configuré ; agent SIEM présent.
const LogMgmtLinuxCmd = `systemctl is-active auditd rsyslog systemd-journald 2>/dev/null | grep -q '^active' && echo yes || echo no; (grep -rqsE '^[^#]*@@?[0-9]' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null && echo yes || echo no); (command -v splunkd filebeat wazuh-agentd auditbeat 2>/dev/null | grep -q . && echo yes || echo no)`

// --- Normalisation brut → LogMgmtEvidence ---

// LogMgmtWindowsNormalizer parse le JSON émis côté Windows :
// {"audit_enabled":bool,"log_forwarding":bool,"siem_present":bool}.
func LogMgmtWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		AuditEnabled  *bool `json:"audit_enabled"`
		LogForwarding *bool `json:"log_forwarding"`
		SiemPresent   *bool `json:"siem_present"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie journalisation illisible : %w", err)
	}
	if w.AuditEnabled == nil {
		return nil, errors.New("champ audit_enabled absent")
	}
	return json.Marshal(LogMgmtEvidence{
		AuditEnabled:  derefBool(w.AuditEnabled),
		LogForwarding: derefBool(w.LogForwarding),
		SiemPresent:   derefBool(w.SiemPresent),
	})
}

// LogMgmtLinuxNormalizer parse 3 lignes yes/no : audit actif ; transfert distant ;
// agent SIEM présent. Une ligne absente vaut « no » ; sortie vide = erreur.
func LogMgmtLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie journalisation vide")
	}
	ev := LogMgmtEvidence{AuditEnabled: ls[0] == "yes"}
	if len(ls) > 1 {
		ev.LogForwarding = ls[1] == "yes"
	}
	if len(ls) > 2 {
		ev.SiemPresent = ls[2] == "yes"
	}
	return json.Marshal(ev)
}

// --- Décodage + évaluation factorisés ---

// decodeLogMgmt factorise le décodage commun aux évaluateurs de la famille : gère la
// collecte échouée et la preuve illisible via errorAssessment (renvoyé si non nil).
func decodeLogMgmt(raw assess.RawEvidence) (LogMgmtEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return LogMgmtEvidence{}, &ha
	}
	var ev LogMgmtEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return LogMgmtEvidence{}, &ha
	}
	return ev, nil
}

// evalLogSignal note un contrôle de la famille à partir d'un unique signal booléen
// (présence/absence du dispositif technique), plafonné à cap. Fonction PURE : la
// décision ne dépend que du booléen ; ev n'est reporté que dans le Detail (traçabilité).
// present → Defined/Pass ; absent → Initial/Fail ; le plafond exprime le caractère MIXTE.
func evalLogSignal(host assess.HostRef, ev LogMgmtEvidence, present bool, cap cyfun.MaturityLevel, label string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"audit_enabled":  ev.AuditEnabled,
		"log_forwarding": ev.LogForwarding,
		"siem_present":   ev.SiemPresent,
	}}
	var lvl cyfun.MaturityLevel
	if present {
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("%s : dispositif technique constaté (rétention, revue et analyse restent à attester).", label)
	} else {
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("%s : aucun dispositif technique constaté (rétention, revue et analyse restent à attester).", label)
	}
	if lvl > cap { // plafond MIXTE : le scan ne prouve pas la maturité du processus.
		lvl = cap
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- DE.CM-01.3 (Important, KEY MEASURE) — détection des connexions non autorisées ---
// Signal : audit/journalisation des connexions activé.

var DECM0103Meta = cyfun.ControlMeta{
	ID: "DE.CM-01.3", Function: cyfun.Detect, Category: "DE.CM", Subcategory: "DE.CM-01",
	Level: cyfun.LevelImportant, KeyMeasure: true,
	Requirement: "The organisation shall monitor and identify unauthorised use of its business-critical systems through the detection of unauthorised local connections, network connections and remote connections.",
}

var DECM0103Questions = []survey.Question{
	survey.Ask("DE.CM-01.3", survey.Documentation, "policy",
		"La détection des connexions locales, réseau et distantes non autorisées est-elle documentée, revue et analysée ?"),
}

// LogConn0103Evaluator (DE.CM-01.3) — MIXTE, plafond Defined.
type LogConn0103Evaluator struct{}

func (LogConn0103Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeLogMgmt(raw)
	if errHA != nil {
		return *errHA
	}
	return evalLogSignal(raw.Host, ev, ev.AuditEnabled, cyfun.Defined, "Journalisation des connexions")
}

// --- PR.PS-04.3 (Important) — déplacement des journaux vers un système alternatif ---
// Signal : transfert de journaux configuré.

var PRPS0403Meta = cyfun.ControlMeta{
	ID: "PR.PS-04.3", Function: cyfun.Protect, Category: "PR.PS", Subcategory: "PR.PS-04",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "Audit data from the organisation's critical systems shall be moved to an alternative system.",
}

var PRPS0403Questions = []survey.Question{
	survey.Ask("PR.PS-04.3", survey.Documentation, "policy",
		"Le transfert des données d'audit vers un système alternatif est-il documenté, revu et analysé ?"),
}

// LogForward0403Evaluator (PR.PS-04.3) — MIXTE, plafond Defined.
type LogForward0403Evaluator struct{}

func (LogForward0403Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeLogMgmt(raw)
	if errHA != nil {
		return *errHA
	}
	return evalLogSignal(raw.Host, ev, ev.LogForwarding, cyfun.Defined, "Transfert des journaux vers un système alternatif")
}

// --- DE.CM-09.1 (Important) — surveillance matériel/logiciel/runtime ---
// Signal : audit/journalisation système activé.

var DECM0901Meta = cyfun.ControlMeta{
	ID: "DE.CM-09.1", Function: cyfun.Detect, Category: "DE.CM", Subcategory: "DE.CM-09",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "The organisation shall monitor computing hardware, software, runtime environments, and their data to detect potentially adverse events.",
}

var DECM0901Questions = []survey.Question{
	survey.Ask("DE.CM-09.1", survey.Documentation, "policy",
		"La surveillance du matériel, des logiciels et des environnements d'exécution est-elle documentée, revue et analysée ?"),
}

// LogMonitor0901Evaluator (DE.CM-09.1) — MIXTE, plafond Defined.
type LogMonitor0901Evaluator struct{}

func (LogMonitor0901Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeLogMgmt(raw)
	if errHA != nil {
		return *errHA
	}
	return evalLogSignal(raw.Host, ev, ev.AuditEnabled, cyfun.Defined, "Surveillance système et applicative")
}

// --- DE.AE-02.1 (Important) — analyse des événements de sécurité ---
// Signal : présence d'un SIEM (analyse des événements).

var DEAE0201Meta = cyfun.ControlMeta{
	ID: "DE.AE-02.1", Function: cyfun.Detect, Category: "DE.AE", Subcategory: "DE.AE-02",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "Cybersecurity and information security events shall be reviewed and analysed to identify potential attack targets and methods, in accordance with applicable laws, regulations, standards, and policies.",
}

var DEAE0201Questions = []survey.Question{
	survey.Ask("DE.AE-02.1", survey.Documentation, "policy",
		"La revue et l'analyse des événements de sécurité sont-elles documentées, revues et analysées ?"),
}

// LogAnalysis0201Evaluator (DE.AE-02.1) — MIXTE, plafond Defined.
type LogAnalysis0201Evaluator struct{}

func (LogAnalysis0201Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeLogMgmt(raw)
	if errHA != nil {
		return *errHA
	}
	return evalLogSignal(raw.Host, ev, ev.SiemPresent, cyfun.Defined, "Analyse des événements de sécurité")
}

// --- DE.AE-03.2 (Important) — agrégation/corrélation multi-sources ---
// Signal : SIEM présent OU transfert de journaux (au moins une source centralisée).

var DEAE0302Meta = cyfun.ControlMeta{
	ID: "DE.AE-03.2", Function: cyfun.Detect, Category: "DE.AE", Subcategory: "DE.AE-03",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "The organisation shall ensure that event data from critical systems is collected and correlated using information from multiple relevant sources.",
}

var DEAE0302Questions = []survey.Question{
	survey.Ask("DE.AE-03.2", survey.Documentation, "policy",
		"La collecte et la corrélation des données d'événements depuis plusieurs sources sont-elles documentées, revues et analysées ?"),
}

// LogCorrelate0302Evaluator (DE.AE-03.2) — MIXTE, plafond Defined.
type LogCorrelate0302Evaluator struct{}

func (LogCorrelate0302Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeLogMgmt(raw)
	if errHA != nil {
		return *errHA
	}
	return evalLogSignal(raw.Host, ev, ev.SiemPresent || ev.LogForwarding, cyfun.Defined, "Agrégation et corrélation des événements")
}

// --- DE.AE-02.2 (Essential) — analyse automatisée des événements détectés ---
// Signal : présence d'un SIEM (mécanisme automatisé d'analyse).

var DEAE0202Meta = cyfun.ControlMeta{
	ID: "DE.AE-02.2", Function: cyfun.Detect, Category: "DE.AE", Subcategory: "DE.AE-02",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall implement automated mechanisms where feasible to review and analyse detected events.",
}

var DEAE0202Questions = []survey.Question{
	survey.Ask("DE.AE-02.2", survey.Documentation, "policy",
		"Les mécanismes automatisés d'analyse des événements détectés sont-ils documentés, revus et analysés ?"),
}

// LogAutoAnalysis0202Evaluator (DE.AE-02.2) — MIXTE, plafond Defined.
type LogAutoAnalysis0202Evaluator struct{}

func (LogAutoAnalysis0202Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeLogMgmt(raw)
	if errHA != nil {
		return *errHA
	}
	return evalLogSignal(raw.Host, ev, ev.SiemPresent, cyfun.Defined, "Analyse automatisée des événements")
}

// --- DE.AE-03.3 (Essential) — combinaison de l'analyse avec d'autres sources ---
// Signal : présence d'un SIEM (plateforme de combinaison des sources).

var DEAE0303Meta = cyfun.ControlMeta{
	ID: "DE.AE-03.3", Function: cyfun.Detect, Category: "DE.AE", Subcategory: "DE.AE-03",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall combine event analysis with information from vulnerability scans, system performance data, monitoring of critical systems, and facility monitoring, where feasible.",
}

var DEAE0303Questions = []survey.Question{
	survey.Ask("DE.AE-03.3", survey.Documentation, "policy",
		"La combinaison de l'analyse des événements avec les scans de vulnérabilités et les données de supervision est-elle documentée, revue et analysée ?"),
}

// LogCombine0303Evaluator (DE.AE-03.3) — MIXTE, plafond Defined.
type LogCombine0303Evaluator struct{}

func (LogCombine0303Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeLogMgmt(raw)
	if errHA != nil {
		return *errHA
	}
	return evalLogSignal(raw.Host, ev, ev.SiemPresent, cyfun.Defined, "Combinaison de l'analyse des événements")
}

// --- PR.PS-04.4 (Essential) — comportement sur échec du traitement d'audit ---
// Signal : audit/journalisation activé (préalable à toute gestion d'échec d'audit).

var PRPS0404Meta = cyfun.ControlMeta{
	ID: "PR.PS-04.4", Function: cyfun.Protect, Category: "PR.PS", Subcategory: "PR.PS-04",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall ensure that audit processing failures on the organisation's systems generate alerts and trigger defined responses.",
}

var PRPS0404Questions = []survey.Question{
	survey.Ask("PR.PS-04.4", survey.Documentation, "policy",
		"Le déclenchement d'alertes et de réponses définies sur échec du traitement d'audit est-il documenté, revu et analysé ?"),
}

// LogAuditFail0404Evaluator (PR.PS-04.4) — MIXTE, plafond Defined.
type LogAuditFail0404Evaluator struct{}

func (LogAuditFail0404Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeLogMgmt(raw)
	if errHA != nil {
		return *errHA
	}
	return evalLogSignal(raw.Host, ev, ev.AuditEnabled, cyfun.Defined, "Comportement sur échec du traitement d'audit")
}
