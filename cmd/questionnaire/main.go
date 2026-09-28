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
	"strings"
	"time"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/engine"
	"github.com/warrox1993/clawkwerk/internal/survey"
	"github.com/warrox1993/clawkwerk/internal/web"
)

// addr est la seule adresse d'écoute autorisée. Constante, pas un flag : on ne
// veut PAS offrir la possibilité d'ouvrir le service sur le réseau.
const addr = "127.0.0.1:8099"

func main() {
	out := flag.String("out", "./responses.json", "fichier de sortie JSON des réponses (permissions 0600)")
	level := flag.String("level", "basic", "niveau d'assurance CyFun : basic | important | essential")
	flag.Parse()

	lvl, err := normalizeLevel(*level)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// Catalogue de questions du niveau choisi (Important et Essential sont des
	// sur-ensembles de Basic).
	questions := engine.AllQuestions(engine.ControlsForLevel(lvl))
	srv := web.New(questions)
	srv.Level = lvl
	// Seuls les noms locaux de CE service sont acceptés dans l'en-tête Host :
	// une page tierce qui ferait résoudre son domaine vers 127.0.0.1 (DNS
	// rebinding) est refusée.
	srv.AllowedHosts = []string{addr, "localhost:8099"}
	// Persistance après chaque soumission ACCEPTÉE (jeton CSRF valide). Le
	// paquet web reste sans I/O disque (testable) ; l'écriture fichier est une
	// décision de CETTE commande.
	srv.OnSubmit = func(r survey.Responses) error { return writeResponses(*out, r) }

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second, // garde-fou basique contre un client lent
	}

	// URL affichée sur STDERR (pas stdout) : stdout peut être réservé à une
	// éventuelle sortie machine ; les messages opérateur vont sur stderr.
	fmt.Fprintf(os.Stderr, "Questionnaire %s (%d questions) disponible sur http://%s/ (Ctrl+C pour arrêter)\n", lvl, len(questions), addr)
	log.Fatal(httpServer.ListenAndServe())
}

// normalizeLevel valide le niveau saisi en CLI (même convention que
// l'orchestrateur).
func normalizeLevel(level string) (string, error) {
	switch strings.ToLower(level) {
	case "basic":
		return cyfun.LevelBasic, nil
	case "important":
		return cyfun.LevelImportant, nil
	case "essential":
		return cyfun.LevelEssential, nil
	default:
		return "", fmt.Errorf("niveau inconnu %q (attendu : basic | important | essential)", level)
	}
}

// writeResponses sérialise les réponses en JSON indenté dans path, avec des
// permissions 0600 (lecture/écriture propriétaire uniquement) : le fichier
// contient des données sensibles, il ne doit pas être lisible par les autres
// utilisateurs de la machine.
func writeResponses(path string, resp survey.Responses) error {
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return err
	}
	// os.WriteFile applique le mode 0600 à la création ; si le fichier existe
	// déjà, ses permissions ne sont pas modifiées, mais on le crée nous-mêmes.
	return os.WriteFile(path, data, 0600)
}
