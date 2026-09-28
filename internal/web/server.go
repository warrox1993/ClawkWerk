// Package web sert l'interface LOCALE de saisie du questionnaire déclaratif.
//
// Pourquoi la stdlib seule (net/http + html/template) : l'outil est livré sur
// une clé USB live-boot offline (voir CLAUDE.md). Aucune ressource externe
// (CDN, police, JS tiers) ne doit être requise pour afficher le formulaire, et
// on veut zéro dépendance nouvelle à auditer. html/template auto-échappe les
// valeurs injectées dans le HTML : les textes de questions et libellés viennent
// de nos catalogues, mais l'auto-échappement est une défense en profondeur
// gratuite contre toute injection si une source de question devenait externe.
package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/url"
	"sync"

	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Server est un http.Handler qui rend le formulaire et encaisse les
// soumissions. Il conserve la DERNIÈRE soumission en mémoire, protégée par un
// mutex car net/http traite chaque requête dans sa propre goroutine : deux
// POST concurrents (ou un GET /Responses pendant un POST) accéderaient sinon à
// la map en course de données.
//
// On ne persiste rien ici : la persistance (fichier JSON) est la responsabilité
// de la commande appelante — le paquet web reste sans I/O disque, donc testable
// sans toucher au système de fichiers.
type Server struct {
	questions []survey.Question  // catalogue plat, ordre stable pour le rendu
	groups    []controlGroup     // questions regroupées par ControlID (ordre de 1re apparition)
	tmpl      *template.Template // template du formulaire, compilé une fois
	mu        sync.Mutex         // protège last
	last      survey.Responses   // dernière soumission reçue (nil tant qu'aucune)
	token     string             // jeton anti-CSRF, tiré au hasard au démarrage

	// Level = niveau d'assurance affiché dans le titre (Basic, Important…).
	Level string
	// AllowedHosts, si non vide, restreint les en-têtes Host acceptés (par
	// exemple "127.0.0.1:8099") : une page tierce qui ferait pointer un nom de
	// domaine sur 127.0.0.1 (DNS rebinding) est refusée.
	AllowedHosts []string
	// OnSubmit, si non nil, reçoit chaque soumission ACCEPTÉE (jeton valide),
	// typiquement pour l'écrire sur disque. Une erreur est renvoyée en 500.
	OnSubmit func(survey.Responses) error
}

// controlGroup = un bloc de contrôle dans le formulaire : son ID sert de titre,
// et ses questions sont rendues à la suite.
type controlGroup struct {
	ControlID string
	Questions []survey.Question
}

// New construit le serveur à partir de la liste plate de questions
// (typiquement engine.AllQuestions(engine.DefaultControls())). Le regroupement
// et la compilation du template sont faits une seule fois ici, pas à chaque
// requête : le rendu d'une page HTTP doit rester bon marché.
func New(questions []survey.Question) *Server {
	s := &Server{
		questions: questions,
		groups:    groupByControl(questions),
		tmpl:      template.Must(template.New("form").Parse(formTmpl)),
		token:     newToken(),
	}
	return s
}

// newToken tire 32 octets aléatoires (crypto/rand) encodés en hexadécimal.
func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("web: générateur aléatoire indisponible : " + err.Error())
	}
	return hex.EncodeToString(b)
}

// CSRFToken renvoie le jeton que le formulaire doit renvoyer (utile aux tests).
func (s *Server) CSRFToken() string { return s.token }

// groupByControl range les questions par ControlID en PRÉSERVANT l'ordre de
// première apparition du contrôle (et l'ordre des questions à l'intérieur).
//
// Pourquoi pas une simple map[string][]Question : itérer une map en Go donne un
// ordre ALÉATOIRE à chaque exécution — le formulaire changerait d'ordre à
// chaque chargement, ce qui déroute le consultant. On garde donc une slice
// ordonnée + une map d'index temporaire pour retrouver le bon groupe en O(1).
func groupByControl(questions []survey.Question) []controlGroup {
	var groups []controlGroup
	index := make(map[string]int) // ControlID -> position dans groups
	for _, q := range questions {
		pos, seen := index[q.ControlID]
		if !seen {
			pos = len(groups)
			index[q.ControlID] = pos
			groups = append(groups, controlGroup{ControlID: q.ControlID})
		}
		groups[pos].Questions = append(groups[pos].Questions, q)
	}
	return groups
}

// ServeHTTP implémente http.Handler et route à la main (pas de mux) : deux
// routes suffisent, un ServeMux serait du cérémonial inutile ici. On teste la
// méthode ET le chemin explicitement pour renvoyer les bons codes d'erreur.
//
// Protection CSRF, en trois couches simples :
//   - l'en-tête Host doit figurer dans AllowedHosts (anti DNS rebinding) ;
//   - un POST portant un en-tête Origin (ou, à défaut, Referer) doit venir de
//     la même origine que le serveur ;
//   - un POST doit renvoyer le jeton aléatoire inséré dans le formulaire, qu'une
//     page tierce ne peut pas lire.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !s.hostAllowed(r.Host) {
		http.Error(w, "hôte non autorisé", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		s.handleForm(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/submit":
		if !sameOrigin(r) {
			http.Error(w, "origine de la requête refusée", http.StatusForbidden)
			return
		}
		s.handleSubmit(w, r)
	default:
		http.NotFound(w, r)
	}
}

// hostAllowed vérifie l'en-tête Host quand une liste blanche est configurée.
func (s *Server) hostAllowed(host string) bool {
	if len(s.AllowedHosts) == 0 {
		return true
	}
	for _, h := range s.AllowedHosts {
		if host == h {
			return true
		}
	}
	return false
}

// sameOrigin : si le navigateur annonce l'origine (Origin, sinon Referer), son
// hôte doit être celui de la requête. Sans aucun des deux en-têtes (client en
// ligne de commande), c'est le jeton qui protège.
func sameOrigin(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return true
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Host == r.Host
}

// handleForm rend le formulaire complet regroupé par contrôle.
func (s *Server) handleForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Groups []controlGroup
		Token  string
		Level  string
		Total  int
	}{s.groups, s.token, s.Level, len(s.questions)}
	// On exécute le template ; une erreur d'exécution (rare) est renvoyée en
	// 500 plutôt que d'écrire une page à moitié rendue.
	if err := s.tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleSubmit transforme le POST en survey.Responses et stocke la soumission.
//
// La forme d'un POST de formulaire (name=question.ID, value=choice.Key) est
// EXACTEMENT celle de survey.Responses (map ID -> Key), d'où une conversion
// directe. On ne retient que les questions connues du catalogue : un champ
// inconnu (formulaire trafiqué) est ignoré, et une question laissée vide n'est
// pas insérée — cohérent avec Questionnaire.Unanswered qui la détectera.
func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "formulaire illisible", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf_token")), []byte(s.token)) != 1 {
		http.Error(w, "jeton de formulaire invalide : rechargez la page du questionnaire", http.StatusForbidden)
		return
	}

	resp := make(survey.Responses)
	for _, q := range s.questions {
		if v := r.PostForm.Get(q.ID); v != "" {
			resp[q.ID] = v
		}
	}

	// Section critique la plus courte possible : on ne verrouille que le temps
	// de remplacer la dernière soumission.
	s.mu.Lock()
	s.last = resp
	s.mu.Unlock()

	if s.OnSubmit != nil {
		if err := s.OnSubmit(resp); err != nil {
			http.Error(w, "réponses reçues mais non enregistrées : "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Answered int
		Total    int
	}{Answered: len(resp), Total: len(s.questions)}
	if err := confirmTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Responses renvoie une COPIE de la dernière soumission (nil si aucune).
//
// Pourquoi une copie : une map Go est une référence. Rendre s.last directement
// laisserait l'appelant lire/muter la map pendant qu'un POST la remplace —
// course de données, et couplage entre l'état interne du serveur et le code
// appelant. La copie est le contrat idiomatique « je te donne un instantané ».
func (s *Server) Responses() survey.Responses {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		return nil
	}
	out := make(survey.Responses, len(s.last))
	for k, v := range s.last {
		out[k] = v
	}
	return out
}

// formTmpl : le gabarit du formulaire. Un seul <form> qui POST vers /submit.
// Chaque question = un fieldset de boutons radio partageant name=question.ID ;
// value=choice.Key est la donnée stable postée, le label affiche le texte
// lisible. Tout est inline (pas de CSS externe) pour rester offline.
const formTmpl = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Questionnaire déclaratif CyFun{{if .Level}} ({{.Level}}){{end}}</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;line-height:1.4}
 h2{border-bottom:2px solid #345;padding-bottom:.2rem;margin-top:2rem}
 fieldset{border:1px solid #ccc;border-radius:6px;margin:1rem 0}
 legend{font-weight:600}
 label{display:block;margin:.2rem 0}
 button{font-size:1rem;padding:.6rem 1.2rem;margin:1.5rem 0}
</style>
</head>
<body>
<h1>Questionnaire déclaratif{{if .Level}}, niveau {{.Level}}{{end}}</h1>
<p>{{.Total}} questions. Auto-évaluation assistée : ne constitue pas une certification officielle CyFun.</p>
<form method="post" action="/submit">
<input type="hidden" name="csrf_token" value="{{.Token}}">
{{range .Groups}}
  <h2>{{.ControlID}}</h2>
  {{range .Questions}}
  <fieldset>
    <legend>{{.Text}}</legend>
    {{$qid := .ID}}
    {{range .Choices}}
    <label><input type="radio" name="{{$qid}}" value="{{.Key}}"> {{.Label}}</label>
    {{end}}
  </fieldset>
  {{end}}
{{end}}
  <button type="submit">Envoyer</button>
</form>
</body>
</html>
`

// confirmTmpl : page de confirmation après un POST réussi. Elle rappelle
// combien de questions ont reçu une réponse — un indicateur immédiat de
// complétude pour le consultant.
var confirmTmpl = template.Must(template.New("confirm").Parse(`<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><title>Réponses enregistrées</title></head>
<body style="font-family:system-ui,sans-serif;max-width:820px;margin:2rem auto">
<h1>Réponses enregistrées</h1>
<p>{{.Answered}} question(s) répondue(s) sur {{.Total}}.</p>
<p><a href="/">Revenir au questionnaire</a></p>
</body>
</html>
`))
