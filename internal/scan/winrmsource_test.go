package scan

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/masterzen/winrm"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

// Les premiers tests vérifient les garde-fous portés par le code (avant toute
// action réseau) et les défauts du constructeur ; les derniers utilisent un
// serveur HTTPS local pour prouver la négociation NTLM et la vérification TLS.
// Le transport a en outre été validé contre un vrai Windows 11 (voir
// docs/methode/validation-reelle-2026-09-28.md).

func TestNewWinRMSource_Defaults(t *testing.T) {
	// timeout <= 0 doit retomber sur la valeur par défaut (15s).
	src := NewWinRMSource(true, 0)
	if src.Timeout != 15*time.Second {
		t.Errorf("timeout par défaut: got %v want 15s", src.Timeout)
	}
	if !src.HTTPS {
		t.Error("HTTPS demandé doit être conservé")
	}
	// Posture sécurisée par défaut : vérification TLS active.
	if src.Insecure {
		t.Error("Insecure doit être false par défaut (vérification TLS active)")
	}
	if src.now == nil {
		t.Error("l'horloge doit être initialisée par le constructeur")
	}

	// Un timeout explicite et positif est conservé tel quel.
	src2 := NewWinRMSource(false, 3*time.Second)
	if src2.Timeout != 3*time.Second {
		t.Errorf("timeout explicite: got %v want 3s", src2.Timeout)
	}
}

func TestWinRMSource_RequiresJournal(t *testing.T) {
	src := NewWinRMSource(true, time.Second)
	_, err := src.Collect(context.Background(), scope.ScopedHost{Transport: scope.WinRM},
		ReadOnlyCommand("X", "windows", "Get-Item"), scope.NewCredential("s", "u", []byte("p")), nil)
	if err == nil {
		t.Fatal("un journal est requis")
	}
}

func TestWinRMSource_RejectsNonReadOnly(t *testing.T) {
	src := NewWinRMSource(true, time.Second)
	// CollectCommand à zéro-valeur : readOnly=false.
	_, err := src.Collect(context.Background(), scope.ScopedHost{Transport: scope.WinRM},
		CollectCommand{ControlID: "X"}, scope.NewCredential("s", "u", []byte("p")), audit.NewMemoryJournal())
	if err == nil {
		t.Fatal("une commande non lecture seule doit être refusée")
	}
}

func TestWinRMSource_RequiresCredentials(t *testing.T) {
	src := NewWinRMSource(true, time.Second)
	_, err := src.Collect(context.Background(), scope.ScopedHost{Transport: scope.WinRM},
		ReadOnlyCommand("X", "windows", "Get-Item"), nil, audit.NewMemoryJournal())
	if err == nil {
		t.Fatal("des credentials sont requis pour WinRM")
	}
}

// --- Validation réelle du 28/09/2026 (Windows 11 25H2) ---

func TestNewWinRMSource_NTLMParDefaut(t *testing.T) {
	// Basic est désactivé d'origine côté Windows : avec Basic seul, toutes les
	// collectes échouaient en 401 sur une configuration WinRM par défaut.
	if got := NewWinRMSource(true, time.Second).Auth; got != AuthNTLM {
		t.Fatalf("authentification par défaut : %q, attendu %q", got, AuthNTLM)
	}
	if !ValidWinRMAuth("ntlm") || !ValidWinRMAuth("basic") || ValidWinRMAuth("kerberos") || ValidWinRMAuth("") {
		t.Fatal("ValidWinRMAuth : ensemble supporté = ntlm | basic")
	}
}

func TestWinRMSource_AuthInconnueRefusee(t *testing.T) {
	src := NewWinRMSource(true, time.Second)
	src.Auth = "digest"
	ep := winrm.NewEndpoint("127.0.0.1", 5986, true, false, nil, nil, nil, time.Second)
	if _, err := src.newClient(ep, scope.NewCredential("s", "u", []byte("p"))); err == nil {
		t.Fatal("une authentification inconnue doit être refusée")
	}
}

func TestWsmanFaultText(t *testing.T) {
	// Forme d'une faute WS-Management (accès refusé au shell WinRS), telle que la
	// renvoie l'hôte ; la bibliothèque ne rapporte que « received error response ».
	body := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code><s:Reason><s:Text xml:lang="fr-BE">Accès refusé. </s:Text></s:Reason><s:Detail><f:WSManFault Code="5"><f:Message>Accès refusé.</f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>`
	err := &winrm.ExecuteCommandError{Inner: errors.New("received error response"), Body: body}
	if got := wsmanFaultText(fmt.Errorf("exécution : %w", err)); got != "Accès refusé." {
		t.Fatalf("texte de faute : %q", got)
	}
	if got := wsmanFaultText(errors.New("autre")); got != "" {
		t.Fatalf("erreur sans corps SOAP : %q", got)
	}
}

func TestWinRMCommandLineLength(t *testing.T) {
	// « powershell.exe -EncodedCommand » + base64(UTF-16LE(préfixe + script)).
	script := "Get-Date"
	full := "$ProgressPreference = 'SilentlyContinue';" + script
	want := len("powershell.exe -EncodedCommand ") + base64.StdEncoding.EncodedLen(2*len(full))
	if got := WinRMCommandLineLength(script); got != want {
		t.Fatalf("longueur : %d, attendu %d", got, want)
	}
	src := NewWinRMSource(true, time.Second)
	long := ReadOnlyCommand("X", "windows", strings.Repeat("a", 4000))
	if _, err := src.Collect(context.Background(), scope.ScopedHost{Transport: scope.WinRM}, long,
		scope.NewCredential("s", "u", []byte("p")), audit.NewMemoryJournal()); err == nil {
		t.Fatal("une sonde trop longue pour cmd.exe doit être refusée avant toute connexion")
	}
}

// Serveur HTTPS de test qui exige Negotiate (comme WinRM d'origine) et enregistre
// les en-têtes Authorization reçus.
func negotiateServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var auths []string
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	return srv, &auths
}

func hostFor(t *testing.T, srv *httptest.Server) scope.ScopedHost {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return scope.ScopedHost{Ref: assess.HostRef{ID: "W", OS: "windows"}, Address: u.Hostname(), Port: port, Transport: scope.WinRM}
}

func TestWinRMSource_NegocieNTLMEtVerifieLAutorite(t *testing.T) {
	srv, auths := negotiateServer(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	src := NewWinRMSource(true, 5*time.Second)
	src.CACert = caPEM
	ev, err := src.Collect(context.Background(), hostFor(t, srv), ReadOnlyCommand("X", "windows", "Get-Date"),
		scope.NewCredential("s", "audit", []byte("secret")), audit.NewMemoryJournal())
	if err != nil {
		t.Fatal(err)
	}
	if ev.CollectErr == "" {
		t.Fatal("le serveur refuse toujours : la collecte doit échouer")
	}
	ntlm := false
	for _, a := range *auths {
		// Message NTLMSSP de négociation : « TlRMTVNTUAAB » = base64("NTLMSSP\x00\x01").
		if strings.HasPrefix(a, "Negotiate TlRMTVNTUAAB") || strings.HasPrefix(a, "NTLM TlRMTVNTUAAB") {
			ntlm = true
		}
		if strings.HasPrefix(a, "Basic ") && strings.Contains(a, base64.StdEncoding.EncodeToString([]byte("audit:secret"))) {
			t.Error("le mot de passe ne doit pas être envoyé en Basic quand NTLM est demandé")
		}
	}
	if !ntlm {
		t.Fatalf("aucune négociation NTLM reçue par le serveur : %q", *auths)
	}
}

func TestWinRMSource_SansAutoriteLeCertificatEstRefuse(t *testing.T) {
	srv, auths := negotiateServer(t)
	src := NewWinRMSource(true, 5*time.Second) // ni CACert ni Insecure
	ev, err := src.Collect(context.Background(), hostFor(t, srv), ReadOnlyCommand("X", "windows", "Get-Date"),
		scope.NewCredential("s", "audit", []byte("secret")), audit.NewMemoryJournal())
	if err != nil {
		t.Fatal(err)
	}
	if ev.CollectErr == "" || !strings.Contains(ev.CollectErr, "certificate") {
		t.Fatalf("certificat inconnu : échec TLS attendu, obtenu %q", ev.CollectErr)
	}
	if len(*auths) != 0 {
		t.Fatal("aucune requête ne doit atteindre un hôte dont le certificat n'est pas vérifié")
	}
}
