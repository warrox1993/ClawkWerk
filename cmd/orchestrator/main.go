// Commande orchestrator : exécute un audit CyFun Basic de bout en bout et
// produit le rapport JSON intermédiaire (+ HTML/XLSX/PDF et historique).
//
// La collecte se fait via -transport : "file" (preuves déjà rapatriées, pour
// le dev) ou "remote" (SSH/WinRM sans agent, sur le périmètre fourni). Le choix
// du transport n'affecte que la construction de la Source (voir transport.go) ;
// tout le reste du pipeline est identique.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/capture"
	"github.com/warrox1993/clawkwerk/internal/engine"
	"github.com/warrox1993/clawkwerk/internal/report"
	"github.com/warrox1993/clawkwerk/internal/scope"
	"github.com/warrox1993/clawkwerk/internal/session"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

func main() {
	scopePath := flag.String("scope", "./sample/scope.json", "périmètre d'audit fourni par le client (JSON : client, machines, transports)")
	evidenceDir := flag.String("evidence", "./sample/evidence", "répertoire des preuves collectées (mode FileSource)")
	responsesPath := flag.String("responses", "./sample/responses.json", "réponses au questionnaire déclaratif (JSON)")
	outPath := flag.String("out", "", "chemin d'export du rapport JSON (défaut : stdout)")
	htmlPath := flag.String("html", "", "chemin d'export du rapport HTML (optionnel)")
	xlsxPath := flag.String("xlsx", "", "chemin d'export du classeur XLSX (optionnel)")
	pdfPath := flag.String("pdf", "", "chemin d'export du rapport PDF (optionnel)")
	historyDB := flag.String("history", "", "base SQLite d'historique consultant (optionnel ; JAMAIS sur la clé USB)")
	transport := flag.String("transport", "file", "mode de collecte : file (preuves locales) | remote (SSH/WinRM sans agent)")
	credsPath := flag.String("creds", "", "fichier JSON des credentials read-only fournis par le client (mode remote)")
	knownHosts := flag.String("known-hosts", "", "fichier known_hosts pour vérifier les clés d'hôte SSH (requis en mode remote)")
	winrmInsecure := flag.Bool("winrm-insecure", false, "désactiver la vérification TLS WinRM (LABO UNIQUEMENT ; préférer -winrm-ca)")
	winrmAuth := flag.String("winrm-auth", "ntlm", "authentification WinRM : ntlm (défaut, comptes locaux et de domaine) | basic (si le client l'a activé)")
	winrmCA := flag.String("winrm-ca", "", "fichier PEM de l'autorité qui a émis le certificat WinRM des hôtes (PKI interne, certificat auto-signé exporté)")
	timeout := flag.Duration("timeout", 15*time.Second, "délai maximum par connexion/commande distante")
	coverage := flag.Bool("coverage", false, "afficher la matrice de couverture des équipements réseau puis quitter")
	preflight := flag.Bool("preflight", false, "reconnaissance du périmètre de droits (lecture seule) : teste ce que le compte de service peut lire, puis quitte — aucune élévation de privilèges")
	captureDir := flag.String("capture", "", "répertoire où enregistrer les sorties BRUTES de collecte (pour bâtir des fixtures golden en pilote) — vide = désactivé")
	overridesPath := flag.String("overrides", "", "corrections consultant de l'Implementation (JSON) — justification obligatoire")
	level := flag.String("level", "basic", "niveau d'assurance CyFun : basic | important | essential")
	flag.Parse()

	// Niveau d'assurance : sélectionne le jeu de contrôles ET les seuils de
	// conformité (Basic 2,5/5 ; Important 3/5).
	auditLevel, err0 := normalizeLevel(*level)
	if err0 != nil {
		fmt.Fprintln(os.Stderr, err0)
		os.Exit(2)
	}

	// Matrice de couverture : état HONNÊTE des adaptateurs réseau (quelles
	// marques couvertes, avec quel niveau de confiance). Aucun « 100 % » implicite.
	if *coverage {
		printNetCoverage()
		return
	}

	started := time.Now()

	// Périmètre FOURNI explicitement par le client (fichier -scope) — aucune
	// découverte réseau. L'exemple livré (sample/scope.json) sert à la démo.
	sc, err := loadScope(*scopePath, started)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// Credentials FOURNIS par le client. En mode remote ils sont OBLIGATOIRES
	// (fichier -creds, jamais générés, jamais persistés ailleurs qu'en RAM). En
	// mode file, aucune connexion n'est établie : un credential factice par
	// référence du périmètre suffit à la traçabilité du journal. Le secret n'est
	// pas sérialisable et est effacé (Zero) en fin de session.
	creds, err := resolveCreds(*transport, *credsPath, sc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer func() {
		for _, c := range creds {
			c.Zero()
		}
	}()

	// Source de collecte selon le mode choisi (file par défaut, remote SSH/WinRM).
	src, err := buildSource(*transport, *evidenceDir, *knownHosts, winrmOptions{Insecure: *winrmInsecure, Auth: *winrmAuth, CAFile: *winrmCA}, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erreur de configuration du transport :", err)
		os.Exit(1)
	}

	controlsReg := engine.ControlsForLevel(auditLevel)

	// Preflight : reconnaissance du périmètre de droits (lecture seule) AVANT
	// l'audit. On teste ce que le compte de service peut lire, on l'affiche, et on
	// quitte — pour provisionner le compte une fois, après quoi les runs sont
	// autonomes. Aucune élévation n'est jamais tentée (règle absolue). Le
	// questionnaire n'intervient pas ici.
	if *preflight {
		pre := &engine.Engine{Source: src, Journal: audit.NewMemoryJournal(), Creds: creds, Controls: controlsReg}
		printPreflight(pre.Preflight(context.Background(), sc))
		return
	}

	// Questionnaire : on construit le catalogue depuis le registre, on charge
	// les réponses du consultant, et on en dérive les deux axes déclaratifs.
	// Séparation stricte : Documentation (tous contrôles) + Implementation
	// (contrôles déclaratifs uniquement) viennent d'ici ; le scan n'alimente
	// que l'Implementation des contrôles scannables.
	questionnaire := survey.New(engine.AllQuestions(controlsReg), nil)
	responses, err := loadResponses(*responsesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erreur de lecture du questionnaire :", err)
		os.Exit(1)
	}
	if missing := questionnaire.Unanswered(responses); len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "Attention : %d question(s) sans réponse — les contrôles concernés seront sous-évalués :\n  %v\n", len(missing), missing)
	}

	// Overrides consultant (optionnels) : corrections tracées de l'Implementation.
	var overrides map[string]engine.Override
	if *overridesPath != "" {
		overrides, err = loadOverrides(*overridesPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "erreur de lecture des overrides :", err)
			os.Exit(1)
		}
	}

	eng := &engine.Engine{
		Source:     src,
		Journal:    audit.NewMemoryJournal(),
		Creds:      creds,
		Controls:   controlsReg,
		DocScores:  questionnaire.ScoreMap(survey.Documentation, responses),
		ImplScores: questionnaire.ScoreMap(survey.Implementation, responses),
		Overrides:  overrides,
	}

	// Capture (optionnelle) des sorties brutes → fixtures golden de pilote, sans
	// travail manuel. Observateur passif : n'altère jamais l'audit.
	if *captureDir != "" {
		sink, err := capture.NewFileSink(*captureDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "erreur capture :", err)
			os.Exit(1)
		}
		eng.Capture = sink.Capture
		fmt.Fprintf(os.Stderr, "Capture des sorties brutes activée → %s (RGPD : relire/anonymiser avant tout commit)\n", *captureDir)
	}

	results, err := eng.Run(context.Background(), sc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erreur d'exécution :", err)
		os.Exit(1)
	}

	sessionID := scope.SessionID(sc.ClientRef, started)
	sess := session.NewAtLevel(sessionID, auditLevel, sc, results, eng.Journal.Entries(), started, time.Now())
	fmt.Fprintf(os.Stderr, "Session d'audit %s : %s, %d machine(s), niveau %s.\n", sessionID, sc.ClientRef, len(sc.Hosts), auditLevel)

	// Contrôle d'intégrité de la preuve d'audit : la chaîne de hachage du journal
	// doit être intacte (aucune entrée modifiée, réordonnée ou supprimée).
	if err := audit.Verify(sess.Journal); err != nil {
		fmt.Fprintln(os.Stderr, "ALERTE intégrité du journal :", err)
	} else {
		fmt.Fprintf(os.Stderr, "Journal d'audit : %d entrées, chaîne d'intégrité vérifiée.\n", len(sess.Journal))
	}
	out, err := sess.ToJSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, "erreur de sérialisation :", err)
		os.Exit(1)
	}

	if *outPath == "" {
		fmt.Println(string(out))
	} else {
		if err := os.WriteFile(*outPath, out, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "erreur d'écriture :", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Rapport écrit dans %s\n", *outPath)
	}

	// Livrables optionnels : rapport HTML et classeur XLSX (générés à partir de
	// la même session, aucune décision supplémentaire).
	if *htmlPath != "" || *xlsxPath != "" || *pdfPath != "" {
		view := report.Build(sess)
		if *htmlPath != "" {
			b, err := report.HTML(view)
			if err != nil {
				fmt.Fprintln(os.Stderr, "erreur génération HTML :", err)
				os.Exit(1)
			}
			if err := os.WriteFile(*htmlPath, b, 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "erreur écriture HTML :", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Rapport HTML écrit dans %s\n", *htmlPath)
		}
		if *xlsxPath != "" {
			b, err := report.XLSX(view)
			if err != nil {
				fmt.Fprintln(os.Stderr, "erreur génération XLSX :", err)
				os.Exit(1)
			}
			if err := os.WriteFile(*xlsxPath, b, 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "erreur écriture XLSX :", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Classeur XLSX écrit dans %s\n", *xlsxPath)
		}
		if *pdfPath != "" {
			b, err := report.PDF(view)
			if err != nil {
				fmt.Fprintln(os.Stderr, "erreur génération PDF :", err)
				os.Exit(1)
			}
			if err := os.WriteFile(*pdfPath, b, 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "erreur écriture PDF :", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Rapport PDF écrit dans %s\n", *pdfPath)
		}
	}

	// Historique consultant optionnel (hors clé USB). L'implémentation dépend du
	// build : réelle avec `-tags history` (tire SQLite), sinon un stub explicite.
	// Le binaire de la clé reste ainsi indépendant de modernc.org/sqlite.
	if *historyDB != "" {
		if err := saveHistory(*historyDB, sess, sc.ClientRef); err != nil {
			fmt.Fprintln(os.Stderr, "erreur historique :", err)
			os.Exit(1)
		}
	}

	// Résumé lisible (stderr, pour ne pas polluer le JSON de stdout).
	c := sess.Conformity
	// L'audit incomplet PRIME sur le verdict : tant qu'un contrôle n'est pas
	// évalué, on ne délivre ni conforme ni non-conforme (complétude d'abord).
	if c.Incomplete {
		fmt.Fprintf(os.Stderr, "\n=== Verdict %s : AUDIT INCOMPLET — %d contrôle(s) à évaluer ===\n", c.Level, len(c.UnassessedControls))
		fmt.Fprintf(os.Stderr, "Maturité partielle (contrôles évalués) : %.2f/5 (seuil %.1f)\n", float64(c.TotalMaturity), float64(c.TotalThreshold))
		fmt.Fprintf(os.Stderr, "À compléter (scan, questionnaire de repli ou override) : %v\n", c.UnassessedControls)
		return
	}
	verdict := "NON CONFORME"
	if c.Conform {
		verdict = "CONFORME"
	}
	fmt.Fprintf(os.Stderr, "\n=== Verdict %s : %s ===\n", c.Level, verdict)
	fmt.Fprintf(os.Stderr, "Maturité totale : %.2f/5 (seuil %.1f)\n", float64(c.TotalMaturity), float64(c.TotalThreshold))
	if len(c.NonConformKeyMeasures) > 0 {
		fmt.Fprintf(os.Stderr, "Key Measures non conformes : %v\n", c.NonConformKeyMeasures)
	}
}

// printPreflight affiche le résultat de la reconnaissance de périmètre de droits :
// un décompte par état, le détail des trous (hors « lisible »), les hôtes à
// provisionner ou à vérifier, puis un verdict qui n'annonce un périmètre
// suffisant que si toutes les collectes applicables ont abouti. Rappelle
// explicitement qu'aucune élévation n'est tentée.
func printPreflight(rows []engine.PreflightRow) {
	s := engine.SummarizePreflight(rows)
	fmt.Fprintln(os.Stderr, "\n=== Preflight — périmètre de droits (lecture seule, aucune élévation) ===")
	fmt.Fprintf(os.Stderr, "%d lisible · %d droits insuffisants · %d preuve illisible · %d injoignable · %d OS non supporté\n",
		s.Counts[engine.ReadyOK], s.Counts[engine.ReadyPrivilege], s.Counts[engine.ReadyUnreadable],
		s.Counts[engine.ReadyUnreachable], s.Counts[engine.ReadyUnsupported])
	for _, r := range rows {
		if r.Status != engine.ReadyOK {
			fmt.Fprintf(os.Stderr, "  [%s] %s / %s — %s\n", r.Status, r.Host, r.ControlID, r.Detail)
		}
	}
	if len(s.ProvisionHosts) > 0 {
		fmt.Fprintf(os.Stderr, "\nÀ provisionner — accorder au compte de service un accès en LECTURE aux ressources ci-dessus sur : %v\n", s.ProvisionHosts)
		fmt.Fprintln(os.Stderr, "Le client accorde l'accès ; l'outil ne se l'arroge jamais (aucune élévation automatique, par conception).")
	}
	if len(s.UnreachableHosts) > 0 {
		fmt.Fprintf(os.Stderr, "\nÀ vérifier — connectivité, transport ou preuves absentes sur : %v\n", s.UnreachableHosts)
	}
	if len(s.UnreadableHosts) > 0 {
		fmt.Fprintf(os.Stderr, "\nÀ vérifier — sorties non interprétables sur : %v\n", s.UnreadableHosts)
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", s.Verdict)
}

// loadResponses lit le fichier de réponses du questionnaire (map questionID ->
// clé de choix). survey.Responses étant une simple map, le décodage JSON est
// direct.
func loadResponses(path string) (survey.Responses, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r survey.Responses
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("JSON de réponses invalide : %w", err)
	}
	return r, nil
}
