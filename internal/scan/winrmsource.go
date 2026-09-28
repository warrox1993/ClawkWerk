package scan

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/masterzen/winrm"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

// WinRMSource collecte la preuve d'un hôte Windows par WinRM, en LECTURE SEULE.
// C'est l'équivalent Windows de SSHSource, derrière RemoteSource pour les
// cibles WinRM. Le script exécuté est du PowerShell de collecte (Get-*, etc.) ;
// aucune primitive d'écriture, d'élévation ou de mouvement latéral n'existe ici.
//
// Garde-fous portés par le code, pas par la discipline :
//   - la commande DOIT être read-only (cmd.IsReadOnly) — refus sinon ;
//   - le journal est requis (collecte non journalisée impossible) ;
//   - les credentials sont requis (jamais générés ni devinés par l'outil) ;
//   - la vérification TLS est ACTIVE par défaut (Insecure=false) : un outil qui
//     audite la sécurité ne doit pas lui-même accepter un certificat quelconque.
type WinRMSource struct {
	// HTTPS choisit le transport chiffré (WinRM sur 5986). Défaut recommandé :
	// true. En clair (5985), les identifiants transitent sans confidentialité de
	// transport — à éviter hors réseau de gestion isolé.
	HTTPS bool
	// Insecure désactive la vérification du certificat TLS de l'hôte.
	// RÉSERVÉ AU LABORATOIRE (certificat auto-signé de test), JAMAIS en
	// production : ignorer la vérification TLS rouvre la porte au MITM que
	// l'audit est censé prévenir. Défaut : false (vérification active).
	Insecure bool
	// CACert = certificat(s) PEM de l'autorité qui a émis le certificat WinRM
	// de l'hôte (PKI interne du client, ou certificat auto-signé exporté). Vide :
	// autorités du système. C'est l'alternative VÉRIFIÉE à Insecure.
	CACert []byte
	// Auth choisit l'authentification : AuthNTLM (défaut) ou AuthBasic.
	Auth string
	// Timeout borne l'établissement de la connexion ET l'exécution de la commande.
	Timeout time.Duration
	now     func() time.Time // injectable pour les tests
}

// Authentifications WinRM supportées.
//
//   - AuthNTLM (défaut) : Negotiate/NTLMv2, activé d'origine sur tout Windows et
//     seul utilisable avec un compte de DOMAINE (DOMAINE\compte). Sur HTTPS, le
//     canal TLS protège le message ; le secret ne transite jamais en clair.
//   - AuthBasic : désactivé d'origine côté Windows (Service/Auth/Basic=false) et
//     limité aux comptes LOCAUX ; à n'utiliser que si le client l'a activé.
//
// Constaté sur Windows 11 25H2 le 28/09/2026 : avec Basic seul, toutes les
// collectes échouaient en « 401 » sur une configuration WinRM par défaut.
const (
	AuthNTLM  = "ntlm"
	AuthBasic = "basic"
)

// ValidWinRMAuth indique si le mode d'authentification demandé est supporté.
func ValidWinRMAuth(auth string) bool { return auth == AuthNTLM || auth == AuthBasic }

// NewWinRMSource construit une source WinRM. https choisit le transport chiffré
// (5986) ; timeout <= 0 prend une valeur par défaut de 15s. Insecure reste à
// false par construction : la vérification TLS est active tant qu'on ne l'active
// pas explicitement (posture sécurisée par défaut).
func NewWinRMSource(https bool, timeout time.Duration) *WinRMSource {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &WinRMSource{HTTPS: https, Auth: AuthNTLM, Timeout: timeout, now: time.Now}
}

// newClient construit le client WinRM selon le mode d'authentification. Seule
// fonction qui voit le secret ; elle ne le copie nulle part.
func (s *WinRMSource) newClient(endpoint *winrm.Endpoint, cred *scope.Credential) (*winrm.Client, error) {
	switch s.Auth {
	case AuthBasic:
		return winrm.NewClient(endpoint, cred.Username, string(cred.Secret()))
	case AuthNTLM, "":
		params := *winrm.DefaultParameters
		params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
		return winrm.NewClientWithParameters(endpoint, cred.Username, string(cred.Secret()), &params)
	default:
		return nil, fmt.Errorf("authentification WinRM inconnue %q (attendu : ntlm | basic)", s.Auth)
	}
}

func (s *WinRMSource) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// winrmPort résout le port d'écoute : celui fourni par le périmètre s'il est
// précisé, sinon le port WinRM standard selon le transport (5986 en HTTPS,
// 5985 en clair).
func winrmPort(host scope.ScopedHost, https bool) int {
	if host.Port != 0 {
		return host.Port
	}
	if https {
		return 5986
	}
	return 5985
}

// Collect ouvre une session WinRM, exécute le script PowerShell de collecte et
// renvoie sa sortie standard dans RawEvidence.Data. Comme pour SSHSource, une
// erreur de transport n'est PAS fatale au pipeline : elle est reportée dans
// CollectErr (l'appelant continue, le rapport signale le trou). Les erreurs de
// configuration (journal absent, commande mutante, credentials absents) sont,
// elles, renvoyées comme erreurs — ce sont des fautes de programmation.
func (s *WinRMSource) Collect(ctx context.Context, host scope.ScopedHost, cmd CollectCommand, cred *scope.Credential, j audit.Journal) (assess.RawEvidence, error) {
	if j == nil {
		return assess.RawEvidence{}, errors.New("scan: journal requis (collecte non journalisée interdite)")
	}
	if !cmd.IsReadOnly() {
		return assess.RawEvidence{}, fmt.Errorf("scan: commande non lecture seule refusée pour %s", cmd.ControlID)
	}
	if cred == nil {
		return assess.RawEvidence{}, errors.New("scan: credentials requis pour WinRM")
	}
	if n := WinRMCommandLineLength(cmd.Script); n > MaxWinRMCommandLine {
		return assess.RawEvidence{}, fmt.Errorf("scan: sonde %s trop longue pour WinRM (%d > %d caractères de ligne de commande)", cmd.ControlID, n, MaxWinRMCommandLine)
	}

	ev := assess.RawEvidence{ControlID: cmd.ControlID, Host: host.Ref, Source: "winrm", CollectedAt: s.clock()}

	// Journalisation AVANT toute action réseau (traçabilité non contournable).
	j.Connection(host.Ref, host.Transport, cred.Username)
	j.Command(host.Ref, cmd.ControlID, cmd.Script)

	out, err := s.run(ctx, host, cred, cmd.Script)
	if err != nil {
		ev.CollectErr = err.Error()
		return ev, nil
	}
	ev.Data = out
	return ev, nil
}

// run établit le client WinRM et exécute le script PowerShell. Le secret n'est
// exposé que le temps de la connexion et n'est copié nulle part ailleurs.
func (s *WinRMSource) run(ctx context.Context, host scope.ScopedHost, cred *scope.Credential, script string) ([]byte, error) {
	port := winrmPort(host, s.HTTPS)

	// NewEndpoint(host, port, https, insecure, CAcert, cert, key, timeout).
	// Sans CACert, la vérification s'appuie sur les autorités système ; avec,
	// sur l'autorité fournie par le client. Insecure (labo) la désactive.
	var ca []byte
	if len(s.CACert) > 0 {
		ca = s.CACert
	}
	endpoint := winrm.NewEndpoint(host.Address, port, s.HTTPS, s.Insecure, ca, nil, nil, s.Timeout)

	client, err := s.newClient(endpoint, cred)
	if err != nil {
		return nil, fmt.Errorf("client WinRM %s:%d : %w", host.Address, port, err)
	}

	// RunPSWithContext encode et exécute le script en PowerShell, capture stdout
	// et stderr séparément, et respecte l'annulation/timeout via ctx. On ne
	// remonte que stdout comme preuve ; un code de sortie non nul (ou stderr)
	// est un échec de collecte (non fatal), pas une faute de programmation.
	stdout, stderr, code, err := client.RunPSWithContext(ctx, script)
	if err != nil {
		if detail := wsmanFaultText(err); detail != "" {
			return nil, fmt.Errorf("exécution WinRM %s:%d : %w : %s", host.Address, port, err, detail)
		}
		return nil, fmt.Errorf("exécution WinRM %s:%d : %w", host.Address, port, err)
	}
	if code != 0 {
		return nil, fmt.Errorf("exécution distante (code %d) : %s", code, stderr)
	}
	return []byte(stdout), nil
}

// wsmanFaultText extrait le texte lisible d'une faute WS-Management (élément
// <s:Text> ou <f:Message>) renvoyée par l'hôte. Sans lui, la bibliothèque ne
// rapporte que « received error response » : impossible de distinguer un accès
// refusé (droits à provisionner) d'une panne. Renvoie "" si rien d'exploitable.
func wsmanFaultText(err error) string {
	var ece *winrm.ExecuteCommandError
	if !errors.As(err, &ece) || ece.Body == "" {
		return ""
	}
	for _, tag := range []string{"Text", "Message"} {
		if t := xmlElementText(ece.Body, tag); t != "" {
			return t
		}
	}
	return ""
}

// xmlElementText renvoie le texte du premier élément de nom local `local`
// (quel que soit son préfixe d'espace de noms), espaces normalisés.
func xmlElementText(doc, local string) string {
	dec := xml.NewDecoder(strings.NewReader(doc))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == local {
			var txt string
			if err := dec.DecodeElement(&txt, &se); err != nil {
				return ""
			}
			return strings.Join(strings.Fields(txt), " ")
		}
	}
}

// MaxWinRMCommandLine est la longueur maximale d'une ligne de commande cmd.exe
// (8191 caractères). La bibliothèque WinRM lance chaque sonde sous la forme
// « powershell.exe -EncodedCommand <base64 UTF-16LE> » dans un shell cmd :
// au-delà, Windows répond « La ligne de commande est trop longue » (constaté le
// 28/09/2026). Un test vérifie que toutes les sondes Windows tiennent dedans.
const MaxWinRMCommandLine = 8191

// WinRMCommandLineLength calcule la longueur de la ligne de commande que la
// bibliothèque WinRM construit pour un script PowerShell (préfixe
// $ProgressPreference ajouté par la bibliothèque, encodage UTF-16LE puis base64).
func WinRMCommandLineLength(script string) int {
	full := "$ProgressPreference = 'SilentlyContinue';" + script
	units := len(utf16.Encode([]rune(full)))
	return len("powershell.exe -EncodedCommand ") + base64.StdEncoding.EncodedLen(2*units)
}
