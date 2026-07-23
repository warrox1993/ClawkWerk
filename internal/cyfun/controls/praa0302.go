package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// PR.AA-03.2 — « Multi-Factor Authentication (MFA) shall be required to access
// the organisation's networks remotely. » KEY MEASURE. Contrôle SCANNABLE mais
// à preuve PARTIELLE / FAIBLE : la MFA elle-même n'est PAS prouvable côté hôte
// — elle vit au niveau de l'IdP / VPN / passerelle, pas dans la configuration
// d'une machine du périmètre. Ce que le scan constate honnêtement, c'est
// UNIQUEMENT le durcissement de l'exposition distante : NLA exigé côté RDP
// (Windows) ou SSH par clé uniquement (Linux). Ce durcissement est nécessaire
// mais pas suffisant pour attester la MFA.
//
// PLAFOND cyfun.Defined (3) : même « accès distant durci » ne prouve pas la MFA ;
// atteindre Managed/Optimizing suppose une preuve organisationnelle (config
// IdP/VPN, override tracé). Le message le rappelle TOUJOURS.

// RemoteMFAEvidence = faits bruts (lecture seule) sur l'exposition distante.
// Hardened = NLA requis côté RDP, ou SSH clé-uniquement côté Linux.
//
// MfaEnforced est la preuve AUTORITAIRE au niveau de l'IdP (Microsoft 365) : quand
// il est non-nil (hôte de plateforme "m365"), l'évaluateur sait que la MFA est
// réellement constatée côté IdP — ce que le côté hôte ne peut pas prouver — et
// dépasse alors le plafond « host-side ». Nil = non mesuré (hôtes classiques).
type RemoteMFAEvidence struct {
	RemoteAccessEnabled bool  `json:"remote_access_enabled"`         // accès distant exposé côté hôte
	Hardened            bool  `json:"hardened"`                      // NLA (RDP) ou clé-uniquement (SSH)
	MfaEnforced         *bool `json:"mfa_enforced,omitempty"`        // preuve IdP M365 (nil = non mesuré)
	LegacyAuthBlocked   bool  `json:"legacy_auth_blocked,omitempty"` // auth héritée bloquée (M365)
}

// PRAA0302Meta : texte officiel du CCB. Key Measure.
var PRAA0302Meta = cyfun.ControlMeta{
	ID:          "PR.AA-03.2",
	Function:    cyfun.Protect,
	Category:    "PR.AA",
	Subcategory: "PR.AA-03",
	Requirement: "Multi-Factor Authentication (MFA) shall be required to access the organisation's networks remotely.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// PRAA0302Questions : volet Documentation. La MFA n'étant pas prouvable côté
// hôte, c'est le questionnaire (preuve organisationnelle) qui porte l'essentiel.
var PRAA0302Questions = []survey.Question{
	survey.Ask("PR.AA-03.2", survey.Documentation, "policy",
		"Le MFA est-il exigé par une règle pour TOUT accès distant (VPN, RDP, webmail, cloud, tiers) ?"),
}

// RemoteMFAEvaluator implémente assess.Evaluator pour PR.AA-03.2.
type RemoteMFAEvaluator struct{}

func (RemoteMFAEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev RemoteMFAEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateRemoteMFA(raw.Host, ev)
}

// evaluateRemoteMFA : règle de décision pure. Le plafond est Defined(3) car la
// MFA n'est jamais prouvée côté hôte ; chaque message renvoie vers l'attestation
// IdP/VPN (preuve organisationnelle / override).
func evaluateRemoteMFA(host assess.HostRef, ev RemoteMFAEvidence) assess.HostAssessment {
	// Preuve AUTORITAIRE au niveau de l'IdP (Microsoft 365) : elle prouve
	// RÉELLEMENT la MFA (ce que le côté hôte ne peut pas), donc elle dépasse le
	// plafond host-side. Le 5 reste réservé à l'override tracé.
	if ev.MfaEnforced != nil {
		f := assess.Finding{HostID: host.ID, Detail: map[string]any{
			"mfa_enforced": *ev.MfaEnforced, "legacy_auth_blocked": ev.LegacyAuthBlocked,
		}}
		var lvl cyfun.MaturityLevel
		switch {
		case *ev.MfaEnforced && ev.LegacyAuthBlocked:
			lvl, f.Status = cyfun.Managed, assess.StatusPass
			f.Message = "MFA imposée au niveau M365 (Security Defaults ou accès conditionnel) ET authentification héritée bloquée."
		case *ev.MfaEnforced:
			lvl, f.Status = cyfun.Managed, assess.StatusPass
			f.Message = "MFA imposée au niveau M365 ; recommandé de bloquer aussi l'authentification héritée."
		default:
			lvl, f.Status = cyfun.Initial, assess.StatusFail
			f.Message = "MFA NON imposée au niveau M365 (ni Security Defaults, ni accès conditionnel exigeant la MFA pour tous)."
		}
		return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
	}
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"remote_access_enabled": ev.RemoteAccessEnabled,
			"hardened":              ev.Hardened,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case !ev.RemoteAccessEnabled:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = "Aucun accès distant exposé côté hôte ; la MFA n'est pas prouvable côté hôte — MFA à attester pour VPN/cloud au niveau IdP/VPN (preuve organisationnelle / override)."
	case ev.Hardened:
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = "Accès distant durci (NLA/clé) ; la MFA n'est pas prouvable côté hôte — attester au niveau IdP/VPN (preuve organisationnelle / override)."
	default:
		lvl, f.Status = cyfun.Repeatable, assess.StatusFail
		f.Message = "Accès distant exposé sans durcissement ni preuve de MFA ; la MFA n'est pas prouvable côté hôte — attester au niveau IdP/VPN (preuve organisationnelle / override)."
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// PRAA0302WinCmd (LECTURE SEULE) : downlevel reg query, émet un JSON
// {remote_access_enabled, hardened}. remote_access_enabled = RDP activé
// (fDenyTSConnections == 0x0) ; hardened = NLA requis (UserAuthentication == 0x1).
const PRAA0302WinCmd = `$deny=@(reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections 2>$null | Select-String '0x0'); $nla=@(reg query "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication 2>$null | Select-String '0x1'); [pscustomobject]@{remote_access_enabled=($deny.Count -gt 0); hardened=($nla.Count -gt 0)} | ConvertTo-Json`

// PRAA0302LinuxCmd (LECTURE SEULE) : 2 lignes yes/no. Ligne 1 = service SSH
// actif ; ligne 2 = authentification par mot de passe désactivée (clé-uniquement).
const PRAA0302LinuxCmd = `systemctl is-active ssh sshd 2>/dev/null | grep -q '^active' && echo yes || echo no; grep -qiE '^[[:space:]]*PasswordAuthentication[[:space:]]+no' /etc/ssh/sshd_config 2>/dev/null && echo yes || echo no`

// --- Normalisation brut → RemoteMFAEvidence ---

// RemoteMFAWindowsNormalizer parse le JSON émis côté Windows :
// {"remote_access_enabled":bool,"hardened":bool}. Erreur si le champ
// remote_access_enabled est absent (preuve incomplète).
func RemoteMFAWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		RemoteAccessEnabled *bool `json:"remote_access_enabled"`
		Hardened            *bool `json:"hardened"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie exposition distante illisible : %w", err)
	}
	if w.RemoteAccessEnabled == nil {
		return nil, errors.New("champ remote_access_enabled absent")
	}
	return json.Marshal(RemoteMFAEvidence{
		RemoteAccessEnabled: derefBool(w.RemoteAccessEnabled),
		Hardened:            derefBool(w.Hardened),
	})
}

// RemoteMFALinuxNormalizer parse 2 lignes yes/no : ligne[0]=="yes" → SSH actif
// (RemoteAccessEnabled) ; ligne[1]=="yes" → clé-uniquement (Hardened).
func RemoteMFALinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie exposition distante vide")
	}
	ev := RemoteMFAEvidence{RemoteAccessEnabled: ls[0] == "yes"}
	if len(ls) > 1 {
		ev.Hardened = ls[1] == "yes"
	}
	return json.Marshal(ev)
}

// PRAA0302M365Cmd : ressource logique lue par le Microsoft365Client (Graph
// read-only) pour PR.AA-03.2 — Security Defaults + accès conditionnel.
const PRAA0302M365Cmd = "mfa"

// M365MFANormalizer transforme l'enveloppe de réponses Graph (via ParseM365MFA)
// en RemoteMFAEvidence portant la preuve IdP AUTORITAIRE (MfaEnforced non-nil) —
// c'est ce qui ferme honnêtement la lacune « MFA non prouvable côté hôte ».
func M365MFANormalizer(raw []byte) (json.RawMessage, error) {
	enforced, legacy, err := ParseM365MFA(raw)
	if err != nil {
		return nil, fmt.Errorf("réponse Graph MFA illisible : %w", err)
	}
	return json.Marshal(RemoteMFAEvidence{MfaEnforced: &enforced, LegacyAuthBlocked: legacy})
}
