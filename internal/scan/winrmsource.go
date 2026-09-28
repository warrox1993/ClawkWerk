package scan

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	// Timeout borne l'établissement de la connexion ET l'exécution de la commande.
	Timeout time.Duration
	now     func() time.Time // injectable pour les tests
}

// NewWinRMSource construit une source WinRM. https choisit le transport chiffré
// (5986) ; timeout <= 0 prend une valeur par défaut de 15s. Insecure reste à
// false par construction : la vérification TLS est active tant qu'on ne l'active
// pas explicitement (posture sécurisée par défaut).
func NewWinRMSource(https bool, timeout time.Duration) *WinRMSource {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &WinRMSource{HTTPS: https, Timeout: timeout, now: time.Now}
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
	// On ne fournit pas de CA/cert client (nil) : la vérification s'appuie sur
	// les autorités système, sauf si Insecure est explicitement activé (labo).
	endpoint := winrm.NewEndpoint(host.Address, port, s.HTTPS, s.Insecure, nil, nil, nil, s.Timeout)

	client, err := winrm.NewClient(endpoint, cred.Username, string(cred.Secret()))
	if err != nil {
		return nil, fmt.Errorf("client WinRM %s:%d : %w", host.Address, port, err)
	}

	// RunPSWithContext encode et exécute le script en PowerShell, capture stdout
	// et stderr séparément, et respecte l'annulation/timeout via ctx. On ne
	// remonte que stdout comme preuve ; un code de sortie non nul (ou stderr)
	// est un échec de collecte (non fatal), pas une faute de programmation.
	stdout, stderr, code, err := client.RunPSWithContext(ctx, script)
	if err != nil {
		return nil, fmt.Errorf("exécution WinRM %s:%d : %w", host.Address, port, err)
	}
	if code != 0 {
		return nil, fmt.Errorf("exécution distante (code %d) : %s", code, stderr)
	}
	return []byte(stdout), nil
}
