package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// PR.PS-05.1 — « Web and e-mail filters shall be installed and used. » NON
// Key Measure. Contrôle SCANNABLE mais à PREUVE PARTIELLE : depuis l'hôte on
// ne constate que la moitié web du contrôle — un proxy web configuré et un
// indice de filtrage DNS. Le filtrage E-MAIL (anti-spam, anti-phishing) est
// rendu côté SERVEUR de messagerie (ou passerelle cloud), donc INOBSERVABLE
// depuis un endpoint. Le scan PLAFONNE donc à Defined (3) et reste toujours
// StatusPartial : le volet messagerie doit être attesté par preuve
// organisationnelle (questionnaire / override tracé), jamais déduit de l'hôte.

// WebFilterEvidence = faits bruts (lecture seule) sur le filtrage web côté hôte.
type WebFilterEvidence struct {
	ProxyConfigured  bool `json:"proxy_configured"`   // proxy web configuré (WPAD/manuel)
	DNSFilteringHint bool `json:"dns_filtering_hint"` // indice de résolveur DNS filtrant
}

// PRPS0501Meta : texte officiel du CCB. Non Key Measure.
var PRPS0501Meta = cyfun.ControlMeta{
	ID:          "PR.PS-05.1",
	Function:    cyfun.Protect,
	Category:    "PR.PS",
	Subcategory: "PR.PS-05",
	Requirement: "Web and e-mail filters shall be installed and used.",
	Level:       "Basic",
	KeyMeasure:  false,
}

// PRPS0501Questions : volet Documentation. Ici il porte aussi le filtrage
// e-mail, inobservable côté hôte — d'où une seule question « policy » couvrant
// les deux volets (web ET messagerie).
var PRPS0501Questions = []survey.Question{
	survey.Ask("PR.PS-05.1", survey.Documentation, "policy",
		"Des filtres web et de messagerie (anti-spam, anti-phishing, filtrage URL/contenu) sont-ils prévus et actifs par une règle ?"),
}

// emailServerAttestation : message CONSTANT rappelant que le filtrage e-mail
// relève d'une preuve organisationnelle, ajouté à chaque constat de ce contrôle.
const emailServerAttestation = "filtrage e-mail serveur à attester (preuve organisationnelle)"

// PRPS0501WinCmd : sonde Windows LECTURE SEULE (JSON). Détecte un proxy web
// via `reg query` downlevel (ProxyEnable=0x1 dans les Internet Settings de
// l'utilisateur courant). Le filtrage DNS n'est pas sondé ici (false).
const PRPS0501WinCmd = `$p=@(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable 2>$null | Select-String '0x1'); [pscustomobject]@{proxy_configured=($p.Count -gt 0); dns_filtering_hint=$false} | ConvertTo-Json`

// PRPS0501LinuxCmd : sonde Linux LECTURE SEULE (2 lignes yes/no) — proxy web
// (variables d'environnement http(s)_proxy OU /etc/environment) ; l'indice DNS
// n'est pas sondé (no).
const PRPS0501LinuxCmd = `(env | grep -qiE 'https?_proxy' || grep -qiE 'proxy' /etc/environment 2>/dev/null) && echo yes || echo no; echo no`

// WebFilterEvaluator implémente assess.Evaluator pour PR.PS-05.1.
type WebFilterEvaluator struct{}

// Evaluate : faits de filtrage web d'UN hôte -> constat + niveau proposé. Pure.
func (WebFilterEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev WebFilterEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateWebFilter(raw.Host, ev)
}

// evaluateWebFilter : règle de décision à PREUVE PARTIELLE. Le statut reste
// toujours StatusPartial et le niveau plafonne à Defined(3), car le volet
// messagerie n'est jamais observable depuis l'hôte.
func evaluateWebFilter(host assess.HostRef, ev WebFilterEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Status: assess.StatusPartial,
		Detail: map[string]any{
			"proxy_configured":   ev.ProxyConfigured,
			"dns_filtering_hint": ev.DNSFilteringHint,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case !ev.ProxyConfigured && !ev.DNSFilteringHint:
		lvl = cyfun.Initial
		f.Message = "aucun filtrage web détecté côté hôte ; " + emailServerAttestation + "."
	case ev.ProxyConfigured && ev.DNSFilteringHint:
		lvl = cyfun.Defined
		f.Message = "filtrage web côté hôte présent ; " + emailServerAttestation + "."
	default:
		lvl = cyfun.Repeatable
		f.Message = "filtrage web partiel côté hôte ; " + emailServerAttestation + "."
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- Normalisation brut → WebFilterEvidence ---

// WebFilterWindowsNormalizer parse le JSON émis par PRPS0501WinCmd :
// {"proxy_configured":bool,"dns_filtering_hint":bool}.
func WebFilterWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		ProxyConfigured  *bool `json:"proxy_configured"`
		DNSFilteringHint *bool `json:"dns_filtering_hint"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie filtrage web illisible : %w", err)
	}
	if w.ProxyConfigured == nil {
		return nil, errors.New("champ proxy_configured absent")
	}
	return json.Marshal(WebFilterEvidence{
		ProxyConfigured:  derefBool(w.ProxyConfigured),
		DNSFilteringHint: derefBool(w.DNSFilteringHint),
	})
}

// WebFilterLinuxNormalizer parse 2 lignes "yes"/"no" émises par PRPS0501LinuxCmd :
// proxy web configuré ; indice de filtrage DNS.
func WebFilterLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie filtrage web vide")
	}
	return json.Marshal(WebFilterEvidence{
		ProxyConfigured:  ls[0] == "yes",
		DNSFilteringHint: len(ls) > 1 && ls[1] == "yes",
	})
}
