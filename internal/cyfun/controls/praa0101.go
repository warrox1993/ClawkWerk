package controls

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// PR.AA-01.1 — « Identities and credentials for authorised users, services, and
// hardware shall be managed. » KEY MEASURE. Contrôle SCANNABLE : on constate sur
// l'hôte la POSTURE technique de gestion des identifiants — politique de mot de
// passe (longueur minimale, expiration), verrouillage de compte après échecs,
// et désactivation du compte invité. Ce sont des faits vérifiables en lecture
// seule ; le PROCESSUS d'approbation/revue des comptes, lui, reste organisationnel
// (axe Documentation via questionnaire). Le scan plafonne donc à Managed (4) :
// le niveau Optimizing (5) s'atteste par preuve organisationnelle (override tracé).

// IdentityEvidence = faits bruts (lecture seule) sur la politique d'identifiants.
type IdentityEvidence struct {
	MinPasswordLength    int  `json:"min_password_length"`    // longueur minimale exigée
	MaxPasswordAgeDays   int  `json:"max_password_age_days"`  // 0 = n'expire jamais
	LockoutThreshold     int  `json:"lockout_threshold"`      // 0 = pas de verrouillage
	GuestAccountDisabled bool `json:"guest_account_disabled"` // compte invité désactivé
}

// PRAA0101Meta : texte officiel du CCB. Key Measure.
var PRAA0101Meta = cyfun.ControlMeta{
	ID:          "PR.AA-01.1",
	Function:    cyfun.Protect,
	Category:    "PR.AA",
	Subcategory: "PR.AA-01",
	Requirement: "Identities and credentials for authorised users, services, and hardware shall be managed.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// PRAA0101Questions : volet Documentation (le scan couvre l'Implementation).
var PRAA0101Questions = []survey.Question{
	survey.Ask("PR.AA-01.1", survey.Documentation, "policy",
		"Un processus documenté gère-t-il le cycle de vie des identités et identifiants (création, revue, révocation, comptes de service) ?"),
}

// Commandes de collecte LECTURE SEULE. Windows : `net accounts` (downlevel,
// disponible de Windows 7 à 11) pour la politique de mot de passe + WMI pour
// l'état du compte invité. Linux : /etc/login.defs avec repli sur
// pwquality.conf, et détection d'un module PAM de verrouillage. Chaque ligne
// Linux émet toujours un jeton concret (jamais de ligne vide) pour préserver le
// décodage positionnel du normaliseur.
const (
	// Émet la sortie BRUTE de `net accounts` (parsée en Go, multilingue) + l'état du
	// compte invité repéré par son RID (501), NEUTRE en langue — contrairement au
	// nom « Guest »/« Invité »/… qui est traduit. GUEST_DISABLED=1 si désactivé/absent.
	PRAA0101WinCmd   = WinPre + `$o=[Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage); $c=[Console]::OutputEncoding; [Console]::OutputEncoding=$o; $t=net accounts; $x=$LASTEXITCODE; [Console]::OutputEncoding=$c; if($x -ne 0){[Console]::Error.WriteLine('PROBE ERROR: net accounts'); exit 1}; $t; try{$u=@(Get-LocalUser -EA Stop)}catch{try{$u=@(Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" -EA Stop|Select-Object SID,@{n='Enabled';e={-not $_.Disabled}})}catch{F 'comptes locaux' $_}}; $g=$u|?{"$($_.SID)" -like '*-501'}; $gd=1; if($g -and $g.Enabled){$gd=0}; "GUEST_DISABLED=$gd"`
	PRAA0101LinuxCmd = `P=/etc/pam.d/common-password; [ -f $P ] || P=/etc/pam.d/system-auth; if grep -qsE '^[^#]*pam_pwquality' $P; then V=$(grep -sE '^[^#]*pam_pwquality' $P | grep -o 'minlen=[0-9]*' | head -1 | cut -d= -f2); [ -z "$V" ] && V=$(grep -hsE '^[[:space:]]*minlen' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' '); V=${V:-8}; elif grep -qsE '^[^#]*pam_unix' $P; then V=$(grep -sE '^[^#]*pam_unix' $P | grep -o 'minlen=[0-9]*' | head -1 | cut -d= -f2); [ -z "$V" ] && grep -sE '^[^#]*pam_unix' $P | grep -qw obscure && V=6; else V=$(grep -E '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' | head -1); fi; echo ${V:-0}; W=$(grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | head -1); echo ${W:-0}; (grep -rqs -e pam_faillock -e pam_tally2 /etc/pam.d 2>/dev/null) && echo yes || echo no; echo yes`
)

// Seuils de robustesse de la politique de mot de passe. Isolés en constantes.
const (
	pwLenStrong = 12 // longueur minimale considérée forte
	pwLenBasic  = 8  // longueur minimale acceptable
)

// IdentityEvaluator implémente assess.Evaluator pour PR.AA-01.1.
type IdentityEvaluator struct{}

func (IdentityEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev IdentityEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateIdentity(raw.Host, ev)
}

func evaluateIdentity(host assess.HostRef, ev IdentityEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"min_password_length":    ev.MinPasswordLength,
			"max_password_age_days":  ev.MaxPasswordAgeDays,
			"lockout_threshold":      ev.LockoutThreshold,
			"guest_account_disabled": ev.GuestAccountDisabled,
		},
	}
	lockout := ev.LockoutThreshold > 0
	var lvl cyfun.MaturityLevel
	switch {
	case ev.MinPasswordLength < pwLenBasic:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("Politique de mot de passe faible ou absente (longueur min %d < %d).", ev.MinPasswordLength, pwLenBasic)
	case ev.MinPasswordLength >= pwLenStrong && lockout && ev.GuestAccountDisabled:
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = fmt.Sprintf("Politique d'identifiants robuste (longueur min %d, verrouillage actif, compte invité désactivé).", ev.MinPasswordLength)
	case ev.MinPasswordLength >= pwLenBasic && lockout && ev.GuestAccountDisabled:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("Politique d'identifiants en place (longueur min %d, verrouillage actif).", ev.MinPasswordLength)
	default:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("Politique partielle (longueur min %d) : verrouillage de compte ou désactivation du compte invité manquant.", ev.MinPasswordLength)
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- Normalisation brut → IdentityEvidence ---

// netAccountLabels = libellés de `net accounts` par langue nationale belge + anglais,
// repliés via foldLower (minuscule + accents retirés) pour comparaison robuste à
// l'encodage. ⚠️ PILOTE : les libellés FR/NL/DE sont fournis en meilleure
// connaissance et DOIVENT être confirmés sur une vraie sortie Windows localisée
// (aucune machine réelle n'a encore validé ces chaînes).
var netAccountLabels = map[string][]string{
	"minlen":  {"minimum password length", "longueur minimale du mot de passe", "minimale wachtwoordlengte", "minimale kennwortlange"},
	"maxage":  {"maximum password age", "duree de vie maximale du mot de passe", "age maximal du mot de passe", "maximale wachtwoordduur", "maximales kennwortalter"},
	"lockout": {"lockout threshold", "seuil de verrouillage", "vergrendelingsdrempel", "drempelwaarde voor accountvergrendeling", "sperrschwelle", "kontosperrungsschwelle"},
}

// IdentityWindowsNormalizer parse la sortie BRUTE de `net accounts` de façon
// MULTILINGUE (EN/FR/NL/DE) : on reconnaît les libellés par langue et on lit la
// valeur numérique après le dernier « : » (une valeur non numérique — Never,
// Jamais, Nooit, Nie… — vaut 0). L'état du compte invité vient de la ligne
// GUEST_DISABLED (repérée par RID, indépendante de la langue).
func IdentityWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie politique d'identifiants vide")
	}
	ev := IdentityEvidence{GuestAccountDisabled: true}
	seenMinLen := false
	for _, line := range ls {
		if strings.HasPrefix(line, "GUEST_DISABLED=") {
			ev.GuestAccountDisabled = strings.TrimSpace(strings.TrimPrefix(line, "GUEST_DISABLED=")) == "1"
			continue
		}
		switch matchNetAccountLabel(foldLower(line)) {
		case "minlen":
			ev.MinPasswordLength = netAccountsValue(line)
			seenMinLen = true
		case "maxage":
			ev.MaxPasswordAgeDays = netAccountsValue(line)
		case "lockout":
			ev.LockoutThreshold = netAccountsValue(line)
		}
	}
	if !seenMinLen {
		return nil, errors.New("longueur minimale de mot de passe introuvable (sortie net accounts inattendue ou langue non reconnue)")
	}
	return json.Marshal(ev)
}

// matchNetAccountLabel renvoie la clé (minlen/maxage/lockout) dont un libellé
// multilingue est contenu dans la ligne repliée, ou "".
func matchNetAccountLabel(folded string) string {
	for key, labels := range netAccountLabels {
		for _, l := range labels {
			if strings.Contains(folded, l) {
				return key
			}
		}
	}
	return ""
}

// netAccountsValue extrait l'entier après le dernier « : » d'une ligne net accounts ;
// une valeur non numérique (Never/Jamais/Nooit/Nie/None…) vaut 0.
func netAccountsValue(line string) int {
	i := strings.LastIndex(line, ":")
	if i < 0 {
		return 0
	}
	if v, ok := atoiSafe(line[i+1:]); ok {
		return v
	}
	return 0
}

// IdentityLinuxNormalizer parse 4 lignes émises côté Linux :
// PASS_MIN_LEN, PASS_MAX_DAYS (/etc/login.defs), présence d'un verrouillage PAM
// ("yes"/"no"), et compte invité désactivé ("yes"/"no" — vrai par défaut sous
// Linux, où aucun compte invité interactif n'existe usuellement).
func IdentityLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie politique d'identifiants vide")
	}
	minLen, ok := atoiSafe(ls[0])
	if !ok {
		return nil, fmt.Errorf("longueur minimale illisible : %q", ls[0])
	}
	ev := IdentityEvidence{MinPasswordLength: minLen, GuestAccountDisabled: true}
	if len(ls) > 1 {
		if v, ok := atoiSafe(ls[1]); ok {
			ev.MaxPasswordAgeDays = v
		}
	}
	if len(ls) > 2 && ls[2] == "yes" {
		ev.LockoutThreshold = 3 // présence d'un verrouillage PAM : valeur symbolique > 0
	}
	if len(ls) > 3 {
		ev.GuestAccountDisabled = ls[3] == "yes"
	}
	return json.Marshal(ev)
}
