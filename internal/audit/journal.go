// Package audit fournit le journal d'audit INALTÉRABLE et NON DÉSACTIVABLE :
// chaque connexion et chaque commande y sont écrites avant exécution. Le
// caractère « non désactivable » est structurel — la couche scan exige un
// Journal en paramètre de collecte, on ne peut pas l'omettre.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"projetcyber/internal/assess"
	"projetcyber/internal/scope"
)

// Kind catégorise une entrée du journal.
type Kind string

const (
	KindConnection Kind = "connection"
	KindCommand    Kind = "command"
	KindResult     Kind = "result"
)

// Entry = une ligne du journal, sérialisable pour la preuve d'audit. Hash est
// le maillon d'une CHAÎNE DE HACHAGE : Hash = sha256(Hash_précédent || champs).
// Toute altération ou réordonnancement d'une entrée casse la chaîne en aval —
// c'est ce qui rend le journal infalsifiable (voir Verify).
type Entry struct {
	At      time.Time `json:"at"`
	Kind    Kind      `json:"kind"`
	HostID  string    `json:"host_id"`
	Control string    `json:"control,omitempty"`
	Detail  string    `json:"detail"`
	Hash    string    `json:"hash"`
}

// chainHash calcule le hash d'une entrée à partir du hash précédent et de ses
// champs (hors Hash lui-même). Format déterministe = reproductible à la
// vérification.
func chainHash(prev string, e Entry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s",
		prev, e.At.UTC().Format(time.RFC3339Nano), e.Kind, e.HostID, e.Control, e.Detail)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify recalcule la chaîne de hachage d'une suite d'entrées (telle que
// renvoyée par Entries) et renvoie une erreur si une entrée a été modifiée,
// supprimée ou réordonnée. C'est le contrôle d'intégrité de la preuve d'audit.
func Verify(entries []Entry) error {
	prev := ""
	for i, e := range entries {
		want := chainHash(prev, e)
		if e.Hash != want {
			return fmt.Errorf("journal altéré à l'entrée %d (hash attendu %s, obtenu %s)", i, want[:12], safeHead(e.Hash))
		}
		prev = e.Hash
	}
	return nil
}

func safeHead(s string) string {
	if len(s) < 12 {
		return s
	}
	return s[:12]
}

// Journal enregistre les actions d'audit. Aucune méthode ne permet de
// l'éteindre ou d'effacer des entrées : par conception.
type Journal interface {
	Connection(host assess.HostRef, t scope.Transport, user string)
	Command(host assess.HostRef, control, cmd string)
	Result(host assess.HostRef, control string, status assess.Status)
	Entries() []Entry
}

// MemoryJournal conserve les entrées en RAM (contrainte stateless : rien n'est
// écrit sur la clé). Thread-safe car les hôtes peuvent être scannés en
// parallèle.
type MemoryJournal struct {
	mu       sync.Mutex
	entries  []Entry
	lastHash string           // dernier maillon de la chaîne de hachage
	now      func() time.Time // injectable pour les tests
}

// NewMemoryJournal crée un journal horodaté par l'horloge système.
func NewMemoryJournal() *MemoryJournal {
	return &MemoryJournal{now: time.Now}
}

func (j *MemoryJournal) add(e Entry) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e.At = j.now()
	e.Hash = chainHash(j.lastHash, e) // chaîne : dépend de l'entrée précédente
	j.lastHash = e.Hash
	j.entries = append(j.entries, e)
}

func (j *MemoryJournal) Connection(host assess.HostRef, t scope.Transport, user string) {
	j.add(Entry{Kind: KindConnection, HostID: host.ID, Detail: string(t) + " en tant que " + user})
}

func (j *MemoryJournal) Command(host assess.HostRef, control, cmd string) {
	j.add(Entry{Kind: KindCommand, HostID: host.ID, Control: control, Detail: cmd})
}

func (j *MemoryJournal) Result(host assess.HostRef, control string, status assess.Status) {
	j.add(Entry{Kind: KindResult, HostID: host.ID, Control: control, Detail: string(status)})
}

// Entries renvoie une COPIE des entrées : l'appelant ne peut pas muter le
// journal a posteriori.
func (j *MemoryJournal) Entries() []Entry {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Entry, len(j.entries))
	copy(out, j.entries)
	return out
}
