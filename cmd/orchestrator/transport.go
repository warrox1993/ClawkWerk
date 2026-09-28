package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/cyfun/controls"
	"github.com/warrox1993/clawkwerk/internal/engine"
	"github.com/warrox1993/clawkwerk/internal/scan"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

// normalizeLevel valide et normalise le niveau d'assurance saisi en CLI
// ("basic"/"important") vers la forme canonique cyfun (Basic/Important).
func normalizeLevel(level string) (string, error) {
	switch level {
	case "basic", "Basic":
		return cyfun.LevelBasic, nil
	case "important", "Important":
		return cyfun.LevelImportant, nil
	case "essential", "Essential":
		return cyfun.LevelEssential, nil
	default:
		return "", fmt.Errorf("niveau inconnu %q (attendu : basic | important | essential)", level)
	}
}

// loadOverrides lit les corrections consultant de l'axe Implementation, par
// contrôle : { "DE.CM-01.2": {"impl": 5, "reason": "preuve d'amélioration
// continue …"} }. La JUSTIFICATION est OBLIGATOIRE (traçabilité d'audit) et le
// niveau doit être 1..5. C'est le seul chemin honnête vers un 5/5 sur un
// contrôle scannable : le consultant l'atteste sur preuve, jamais l'outil seul.
func loadOverrides(path string) (map[string]engine.Override, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]struct {
		Impl   int    `json:"impl"`
		Reason string `json:"reason"`
		Na     bool   `json:"na"` // marquer le contrôle « non applicable »
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("JSON d'overrides invalide : %w", err)
	}
	out := make(map[string]engine.Override, len(raw))
	for id, o := range raw {
		if o.Reason == "" {
			return nil, fmt.Errorf("override %s : justification obligatoire (preuve d'audit)", id)
		}
		if o.Na {
			out[id] = engine.Override{NotApplicable: true, Reason: o.Reason}
			continue
		}
		if o.Impl < 1 || o.Impl > 5 {
			return nil, fmt.Errorf("override %s : niveau %d hors plage 1..5", id, o.Impl)
		}
		out[id] = engine.Override{Impl: cyfun.MaturityLevel(o.Impl), Reason: o.Reason}
	}
	return out, nil
}

// printNetCoverage affiche la matrice de couverture des adaptateurs de pare-feu
// réseau (contrôle PR.IR-01.1) : plateforme, constructeur, statut de fiabilité.
// Le but est la TRANSPARENCE : on ne prétend jamais couvrir « 100 % du marché »,
// on montre exactement ce qui est implémenté, écrit d'après doc, ou à faire.
func printNetCoverage() {
	table := func(title string, rows []controls.NetAdapter) {
		fmt.Printf("\n%s\n", title)
		fmt.Printf("%-12s %-22s %s\n", "PLATEFORME", "CONSTRUCTEUR", "STATUT")
		for _, a := range rows {
			fmt.Printf("%-12s %-22s %s\n", a.Platform, a.Vendor, a.Status)
		}
	}
	fmt.Println("Couverture des équipements réseau (statut HONNÊTE par marque)")
	table("Contrôle PR.IR-01.1 — pare-feu", controls.NetFirewallCoverage())
	table("Contrôle PR.IR-01.2 — segmentation", controls.NetSegmentationCoverage())
	table("Contrôle PR.PS-04.1 — journalisation", controls.NetLoggingCoverage())
	fmt.Println("\nStatuts : validé-matériel = testé sur équipement réel ;")
	fmt.Println("          d'après-doc-non-validé = commandes issues de la doc, à valider au banc ;")
	fmt.Println("          non-implémenté = plateforme reconnue, adaptateur à écrire.")
}

// buildSource construit la Source de collecte selon le mode demandé :
//   - "file"   : FileSource (preuves déjà rapatriées) — mode de dev/PoC ;
//   - "remote" : RemoteSource sans agent, qui aiguille chaque hôte vers SSH
//     (Linux) ou WinRM (Windows) selon son Transport déclaré dans le périmètre.
//
// En mode remote, la vérification de la clé d'hôte SSH est OBLIGATOIRE : on
// exige un fichier known_hosts. Un outil qui audite la sécurité ne se connecte
// jamais à un hôte non vérifié (risque MITM) — d'où l'échec explicite si
// -known-hosts manque.
// winrmOptions regroupe les réglages WinRM de la ligne de commande.
type winrmOptions struct {
	Insecure bool   // -winrm-insecure : vérification TLS désactivée (labo)
	Auth     string // -winrm-auth : ntlm (défaut) | basic
	CAFile   string // -winrm-ca : autorité PEM qui a émis le certificat WinRM des hôtes
}

func buildSource(transport, evidenceDir, knownHostsPath string, wopt winrmOptions, timeout time.Duration) (scan.Source, error) {
	switch transport {
	case "file":
		return scan.NewFileSource(evidenceDir), nil

	case "remote":
		if knownHostsPath == "" {
			return nil, fmt.Errorf("mode remote : -known-hosts requis (vérification de la clé d'hôte SSH, anti-MITM)")
		}
		hostKey, err := knownhosts.New(knownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("known_hosts illisible (%s) : %w", knownHostsPath, err)
		}
		winrm := scan.NewWinRMSource(true, timeout)
		winrm.Insecure = wopt.Insecure // ne désactiver la vérif TLS qu'en labo
		if wopt.Auth != "" {
			if !scan.ValidWinRMAuth(wopt.Auth) {
				return nil, fmt.Errorf("-winrm-auth %q inconnu (attendu : ntlm | basic)", wopt.Auth)
			}
			winrm.Auth = wopt.Auth
		}
		if wopt.CAFile != "" {
			ca, err := os.ReadFile(wopt.CAFile)
			if err != nil {
				return nil, fmt.Errorf("autorité WinRM illisible (%s) : %w", wopt.CAFile, err)
			}
			if !x509.NewCertPool().AppendCertsFromPEM(ca) {
				return nil, fmt.Errorf("autorité WinRM %s : aucun certificat PEM valide", wopt.CAFile)
			}
			winrm.CACert = ca
		}
		return scan.RemoteSource{
			SSH:   scan.NewSSHSource(hostKey, timeout),
			WinRM: winrm,
			// Transport API pour les équipements sans CLI (UniFi), pilotés par API
			// (Sophos), et le tenant Microsoft 365 (Graph read-only). wopt.Insecure
			// sert de drapeau TLS-labo commun.
			API: scan.NewAPISource(timeout, wopt.Insecure, scan.NewUniFiClient(), scan.NewSophosClient(), scan.Microsoft365Client{}),
		}, nil

	default:
		return nil, fmt.Errorf("transport inconnu %q (attendu : file | remote)", transport)
	}
}

// credEntry = forme JSON d'un credential fourni par le client.
type credEntry struct {
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

// loadCreds charge les credentials read-only depuis un fichier JSON de la forme
// { "svc-audit-ro": {"username":"...","secret":"..."} }. Sur la clé USB
// live-boot, ce fichier ne doit vivre qu'en RAM (tmpfs) et être détruit en fin
// de session : le secret n'est jamais recopié dans le rapport (champ non
// sérialisable) et est effacé (Zero) par l'appelant.
func loadCreds(path string) (map[string]*scope.Credential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]credEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("JSON de credentials invalide : %w", err)
	}
	creds := make(map[string]*scope.Credential, len(raw))
	for ref, c := range raw {
		creds[ref] = scope.NewCredential(ref, c.Username, []byte(c.Secret))
	}
	return creds, nil
}

// loadScope charge le périmètre fourni (-scope) et refuse toute plateforme
// inconnue du registre : une faute de frappe dans « os » donnerait sinon des
// « non applicable » silencieux au lieu d'un audit.
func loadScope(path string, now time.Time) (scope.AuditScope, error) {
	if path == "" {
		return scope.AuditScope{}, fmt.Errorf("-scope requis : fichier JSON du périmètre fourni par le client")
	}
	sc, err := scope.LoadFile(path, now)
	if err != nil {
		return scope.AuditScope{}, err
	}
	for _, h := range sc.Hosts {
		if !engine.IsKnownPlatform(h.Ref.OS) {
			return scope.AuditScope{}, fmt.Errorf("périmètre : plateforme %q inconnue pour %s (connues : %v)", h.Ref.OS, h.Ref.ID, engine.KnownPlatforms())
		}
	}
	return sc, nil
}

// resolveCreds fournit les credentials du périmètre. En mode remote, le fichier
// -creds est obligatoire et doit couvrir chaque cred_ref du périmètre : on
// échoue AVANT toute connexion plutôt que de découvrir le trou en cours d'audit.
// En mode file (preuves déjà rapatriées, aucune connexion), un credential
// factice par référence suffit à tracer le compte dans le journal.
func resolveCreds(transport, credsPath string, sc scope.AuditScope) (map[string]*scope.Credential, error) {
	if credsPath == "" {
		if transport == "remote" {
			return nil, fmt.Errorf("mode remote : -creds requis (comptes de service en lecture seule fournis par le client)")
		}
		creds := make(map[string]*scope.Credential)
		for _, ref := range sc.CredRefs() {
			creds[ref] = scope.NewCredential(ref, ref, []byte("demo-not-a-real-secret"))
		}
		return creds, nil
	}
	creds, err := loadCreds(credsPath)
	if err != nil {
		return nil, fmt.Errorf("erreur de lecture des credentials : %w", err)
	}
	for _, ref := range sc.CredRefs() {
		if _, ok := creds[ref]; !ok {
			for _, c := range creds {
				c.Zero()
			}
			return nil, fmt.Errorf("credentials : référence %q du périmètre absente de %s", ref, credsPath)
		}
	}
	return creds, nil
}
