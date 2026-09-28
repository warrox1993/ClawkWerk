// Commande questionnaire : sert l'interface web LOCALE de saisie du
// questionnaire déclaratif CyFun, et écrit les réponses en JSON à chaque
// soumission.
//
// Contrainte de sécurité (voir CLAUDE.md) : les réponses décrivent la posture
// de sécurité d'un client — données sensibles. Le serveur est donc lié
// STRICTEMENT à 127.0.0.1 : jamais "0.0.0.0" ni "" (qui écouteraient sur toutes
// les interfaces et exposeraient le questionnaire au réseau local). L'écoute est
// purement loopback : rien ne sort de la machine du consultant.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/warrox1993/clawkwerk/internal/engine"
	"github.com/warrox1993/clawkwerk/internal/web"
)

// addr est la seule adresse d'écoute autorisée. Constante, pas un flag : on ne
// veut PAS offrir la possibilité d'ouvrir le service sur le réseau.
const addr = "127.0.0.1:8099"

func main() {
	out := flag.String("out", "./responses.json", "fichier de sortie JSON des réponses (permissions 0600)")
	flag.Parse()

	// Catalogue de questions issu du registre des contrôles.
	questions := engine.AllQuestions(engine.DefaultControls())
	srv := web.New(questions)

	// On enveloppe le handler web pour, APRÈS une soumission réussie, persister
	// les réponses. Pourquoi un wrapper plutôt que modifier le paquet web : le
	// paquet web reste sans I/O disque (testable, réutilisable) ; l'écriture
	// fichier est une décision de CETTE commande.
	handler := http.NewServeMux()
	handler.Handle("/", srv)
	handler.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		srv.ServeHTTP(w, r) // laisse le serveur web parser et stocker la soumission
		if r.Method == http.MethodPost {
			if err := writeResponses(*out, srv.Responses()); err != nil {
				// On journalise sans casser l'expérience : la page de
				// confirmation a déjà été envoyée au consultant.
				log.Printf("écriture de %s impossible : %v", *out, err)
			}
		}
	})

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second, // garde-fou basique contre un client lent
	}

	// URL affichée sur STDERR (pas stdout) : stdout peut être réservé à une
	// éventuelle sortie machine ; les messages opérateur vont sur stderr.
	fmt.Fprintf(os.Stderr, "Questionnaire disponible sur http://%s/ (Ctrl+C pour arrêter)\n", addr)
	log.Fatal(httpServer.ListenAndServe())
}

// writeResponses sérialise les réponses en JSON indenté dans path, avec des
// permissions 0600 (lecture/écriture propriétaire uniquement) : le fichier
// contient des données sensibles, il ne doit pas être lisible par les autres
// utilisateurs de la machine.
func writeResponses(path string, resp interface{}) error {
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return err
	}
	// os.WriteFile applique le mode 0600 à la création ; si le fichier existe
	// déjà, ses permissions ne sont pas modifiées, mais on le crée nous-mêmes.
	return os.WriteFile(path, data, 0600)
}
