package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"projetcyber/internal/assess"
	"projetcyber/internal/audit"
	"projetcyber/internal/scope"
)

// SSHSource collecte la preuve d'un hôte Linux par SSH, en LECTURE SEULE.
// C'est le transport réel derrière RemoteSource pour les cibles SSH.
//
// Garde-fous portés par le code, pas par la discipline :
//   - la commande DOIT être read-only (cmd.IsReadOnly) — refus sinon ;
//   - le journal est requis (collecte non journalisée impossible) ;
//   - HostKey (vérification de la clé d'hôte) est REQUIS : sans politique de
//     clé explicite, on refuse de se connecter. Un outil qui audite la sécurité
//     ne doit pas lui-même accepter n'importe quel hôte (risque MITM). On
//     n'expose donc AUCUN raccourci « ignorer la clé » par défaut.
//
// Aucune primitive d'écriture, d'élévation ou de mouvement latéral n'existe ici.
type SSHSource struct {
	// HostKey vérifie la clé publique de l'hôte. Obligatoire. Utiliser
	// ssh.FixedHostKey(clé attendue) ou knownhosts.New(...). nil => refus.
	HostKey ssh.HostKeyCallback
	// Timeout borne la connexion ET l'exécution de la commande.
	Timeout time.Duration
	now     func() time.Time // injectable pour les tests
}

// NewSSHSource construit une source SSH avec une politique de clé d'hôte et un
// timeout. hostKey est obligatoire ; timeout <= 0 prend une valeur par défaut.
func NewSSHSource(hostKey ssh.HostKeyCallback, timeout time.Duration) *SSHSource {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &SSHSource{HostKey: hostKey, Timeout: timeout, now: time.Now}
}

func (s *SSHSource) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Collect ouvre une session SSH, exécute la commande de collecte et renvoie sa
// sortie brute dans RawEvidence.Data. Une erreur de transport n'est pas fatale
// pour le pipeline : elle est reportée dans CollectErr (l'appelant continue et
// le rapport signale le trou). Les erreurs de configuration (journal absent,
// commande mutante, politique de clé absente) sont, elles, renvoyées comme
// erreurs — ce sont des fautes de programmation, pas des trous de couverture.
func (s *SSHSource) Collect(ctx context.Context, host scope.ScopedHost, cmd CollectCommand, cred *scope.Credential, j audit.Journal) (assess.RawEvidence, error) {
	if j == nil {
		return assess.RawEvidence{}, errors.New("scan: journal requis (collecte non journalisée interdite)")
	}
	if !cmd.IsReadOnly() {
		return assess.RawEvidence{}, fmt.Errorf("scan: commande non lecture seule refusée pour %s", cmd.ControlID)
	}
	if s.HostKey == nil {
		return assess.RawEvidence{}, errors.New("scan: politique de clé d'hôte requise (aucune connexion sans vérification)")
	}
	if cred == nil {
		return assess.RawEvidence{}, errors.New("scan: credentials requis pour SSH")
	}

	ev := assess.RawEvidence{ControlID: cmd.ControlID, Host: host.Ref, Source: "ssh", CollectedAt: s.clock()}

	// Journalisation AVANT toute action réseau (traçabilité non contournable).
	j.Connection(host.Ref, host.Transport, cred.Username)
	j.Command(host.Ref, cmd.ControlID, cmd.Script)

	auth, err := sshAuth(cred)
	if err != nil {
		ev.CollectErr = "authentification : " + err.Error()
		return ev, nil
	}
	cfg := &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            auth,
		HostKeyCallback: s.HostKey,
		Timeout:         s.Timeout,
	}

	out, err := runSSH(ctx, address(host), cfg, cmd.Script, s.Timeout)
	if err != nil {
		ev.CollectErr = err.Error()
		return ev, nil
	}
	ev.Data = out
	return ev, nil
}

// sshAuth choisit la méthode d'authentification à partir du secret fourni : si
// le secret est une clé privée PEM, on fait de l'authentification par clé ;
// sinon on le traite comme un mot de passe. Le secret n'est jamais copié
// ailleurs qu'ici, le temps de la connexion.
func sshAuth(cred *scope.Credential) ([]ssh.AuthMethod, error) {
	secret := cred.Secret()
	if signer, err := ssh.ParsePrivateKey(secret); err == nil {
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	if len(secret) == 0 {
		return nil, errors.New("secret vide")
	}
	return []ssh.AuthMethod{ssh.Password(string(secret))}, nil
}

// address résout l'adresse de connexion (port 22 par défaut).
func address(host scope.ScopedHost) string {
	port := host.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(host.Address, strconv.Itoa(port))
}

// runSSH établit la connexion (en respectant ctx pour la phase de dial),
// exécute la commande et renvoie la sortie standard. La commande est bornée par
// timeout et par l'annulation du contexte.
func runSSH(ctx context.Context, addr string, cfg *ssh.ClientConfig, script string, timeout time.Duration) ([]byte, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connexion %s : %w", addr, err)
	}
	// La poignée de main SSH s'effectue sur conn ; on ferme conn via le client.
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake SSH : %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("session SSH : %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(script) }()

	select {
	case <-ctx.Done():
		sess.Signal(ssh.SIGTERM)
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			// Sortie non nulle : on renvoie stderr comme cause, mais la commande
			// de collecte a bien tourné — c'est un échec de collecte, pas fatal.
			return nil, fmt.Errorf("exécution distante : %v : %s", err, stderr.String())
		}
		return stdout.Bytes(), nil
	}
}
