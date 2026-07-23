package scan

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"projetcyber/internal/assess"
	"projetcyber/internal/audit"
	"projetcyber/internal/scope"
)

// startTestSSHServer démarre un serveur SSH minimal sur 127.0.0.1:0 qui accepte
// un mot de passe donné et répond à toute commande exec par `output`. Il permet
// de tester le vrai client x/crypto/ssh sans hôte réel. Renvoie l'adresse
// d'écoute et la clé publique de l'hôte (pour épingler côté client).
func startTestSSHServer(t *testing.T, password string, output []byte) (addr string, hostPub ssh.PublicKey) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == password {
				return &ssh.Permissions{}, nil
			}
			return nil, errBadPassword
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		nConn, err := ln.Accept()
		if err != nil {
			return // listener fermé en fin de test
		}
		serveOneSSH(nConn, cfg, output)
	}()

	return ln.Addr().String(), signer.PublicKey()
}

var errBadPassword = &sshError{"mot de passe invalide"}

type sshError struct{ msg string }

func (e *sshError) Error() string { return e.msg }

// serveOneSSH traite une connexion : handshake, puis répond à un exec par output.
func serveOneSSH(nConn net.Conn, cfg *ssh.ServerConfig, output []byte) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		nConn.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "seule 'session' est supportée")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range chReqs {
				if req.Type == "exec" {
					_, _ = ch.Write(output)
					req.Reply(true, nil)
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					ch.Close()
					return
				}
				req.Reply(false, nil)
			}
		}()
	}
}

func TestSSHSource_Collect_Success(t *testing.T) {
	want := []byte(`{"present":true,"enabled":true}`)
	addr, pub := startTestSSHServer(t, "s3cret", want)
	h, p := splitHostPort(t, addr)

	src := NewSSHSource(ssh.FixedHostKey(pub), 5*time.Second)
	host := scope.ScopedHost{
		Ref: assess.HostRef{ID: "SRV01", OS: "linux"}, Address: h, Port: p, Transport: scope.SSH,
	}
	cmd := ReadOnlyCommand("DE.CM-01.2", "linux", "cat /tmp/av.json")
	cred := scope.NewCredential("svc", "auditor", []byte("s3cret"))
	j := audit.NewMemoryJournal()

	ev, err := src.Collect(context.Background(), host, cmd, cred, j)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if ev.CollectErr != "" {
		t.Fatalf("collecte en erreur inattendue: %s", ev.CollectErr)
	}
	if string(ev.Data) != string(want) {
		t.Errorf("sortie: got %q want %q", ev.Data, want)
	}
	if ev.Source != "ssh" {
		t.Errorf("source: got %q", ev.Source)
	}
	if len(j.Entries()) == 0 {
		t.Error("la connexion et la commande doivent être journalisées")
	}
}

func TestSSHSource_RejectsNonReadOnly(t *testing.T) {
	src := NewSSHSource(ssh.FixedHostKey(dummyKey(t)), time.Second)
	// CollectCommand à zéro-valeur : readOnly=false.
	_, err := src.Collect(context.Background(), scope.ScopedHost{Transport: scope.SSH},
		CollectCommand{ControlID: "X"}, scope.NewCredential("s", "u", []byte("p")), audit.NewMemoryJournal())
	if err == nil {
		t.Fatal("une commande non lecture seule doit être refusée")
	}
}

func TestSSHSource_RequiresHostKeyPolicy(t *testing.T) {
	src := &SSHSource{HostKey: nil, Timeout: time.Second} // aucune politique de clé
	_, err := src.Collect(context.Background(), scope.ScopedHost{Transport: scope.SSH},
		ReadOnlyCommand("X", "linux", "true"), scope.NewCredential("s", "u", []byte("p")), audit.NewMemoryJournal())
	if err == nil {
		t.Fatal("sans politique de clé d'hôte, la connexion doit être refusée")
	}
}

func TestSSHSource_RequiresJournal(t *testing.T) {
	src := NewSSHSource(ssh.FixedHostKey(dummyKey(t)), time.Second)
	_, err := src.Collect(context.Background(), scope.ScopedHost{Transport: scope.SSH},
		ReadOnlyCommand("X", "linux", "true"), scope.NewCredential("s", "u", []byte("p")), nil)
	if err == nil {
		t.Fatal("un journal est requis")
	}
}

func TestSSHSource_BadHostKeyFails(t *testing.T) {
	addr, _ := startTestSSHServer(t, "pw", []byte("x"))
	h, p := splitHostPort(t, addr)
	// On épingle une AUTRE clé que celle du serveur : la connexion doit échouer.
	src := NewSSHSource(ssh.FixedHostKey(dummyKey(t)), 3*time.Second)
	host := scope.ScopedHost{Ref: assess.HostRef{ID: "SRV01", OS: "linux"}, Address: h, Port: p, Transport: scope.SSH}
	ev, err := src.Collect(context.Background(), host, ReadOnlyCommand("X", "linux", "true"),
		scope.NewCredential("s", "u", []byte("pw")), audit.NewMemoryJournal())
	if err != nil {
		t.Fatalf("erreur de config inattendue: %v", err)
	}
	if ev.CollectErr == "" {
		t.Fatal("une clé d'hôte non conforme doit produire une erreur de collecte (MITM)")
	}
}

// --- helpers ---

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p := 0
	for _, c := range ps {
		p = p*10 + int(c-'0')
	}
	return h, p
}

func dummyKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sk
}
