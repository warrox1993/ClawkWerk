package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// testQuestions fabrique un petit catalogue déterministe, indépendant du vrai
// registre : un test unitaire ne doit pas dépendre du contenu métier qui peut
// évoluer. Deux contrôles, pour vérifier aussi le regroupement.
func testQuestions() []survey.Question {
	return []survey.Question{
		{
			ID:        "ID.AM-01/documentation/inventaire",
			ControlID: "ID.AM-01",
			Axis:      survey.Documentation,
			Text:      "Existe-t-il un inventaire des actifs matériels ?",
			Choices: []survey.Choice{
				{Key: "none", Label: "Inexistant", Level: cyfun.Initial},
				{Key: "defined", Label: "Formalisé", Level: cyfun.Defined},
			},
		},
		{
			ID:        "GV.PO-01/documentation/politique",
			ControlID: "GV.PO-01",
			Axis:      survey.Documentation,
			Text:      "Une politique de sécurité est-elle approuvée ?",
			Choices: []survey.Choice{
				{Key: "none", Label: "Inexistant", Level: cyfun.Initial},
				{Key: "defined", Label: "Formalisé", Level: cyfun.Defined},
			},
		},
	}
}

// TestGetFormAffiche vérifie que GET / renvoie 200 et contient le texte d'une
// question connue — preuve que le formulaire est bien rendu.
func TestGetFormAffiche(t *testing.T) {
	srv := New(testQuestions())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code attendu 200, obtenu %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Existe-t-il un inventaire des actifs matériels ?") {
		t.Errorf("le corps ne contient pas le texte de la question attendue")
	}
	// Le titre de contrôle (groupement) doit aussi apparaître.
	if !strings.Contains(body, "ID.AM-01") {
		t.Errorf("le corps ne contient pas le titre de contrôle ID.AM-01")
	}
}

// TestPostSubmitConstruitResponses vérifie que POST /submit convertit bien les
// valeurs de formulaire en survey.Responses, récupérables via Responses().
func TestPostSubmitConstruitResponses(t *testing.T) {
	srv := New(testQuestions())

	form := url.Values{}
	form.Set("csrf_token", srv.CSRFToken())
	form.Set("ID.AM-01/documentation/inventaire", "defined")
	form.Set("GV.PO-01/documentation/politique", "none")

	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code attendu 200, obtenu %d", rec.Code)
	}

	got := srv.Responses()
	if len(got) != 2 {
		t.Fatalf("2 réponses attendues, obtenu %d : %v", len(got), got)
	}
	if got["ID.AM-01/documentation/inventaire"] != "defined" {
		t.Errorf("réponse inventaire attendue \"defined\", obtenu %q", got["ID.AM-01/documentation/inventaire"])
	}
	if got["GV.PO-01/documentation/politique"] != "none" {
		t.Errorf("réponse politique attendue \"none\", obtenu %q", got["GV.PO-01/documentation/politique"])
	}
}

// TestResponsesEstUneCopie garantit que muter la valeur renvoyée n'altère pas
// l'état interne du serveur (contrat « instantané »).
func TestResponsesEstUneCopie(t *testing.T) {
	srv := New(testQuestions())
	form := url.Values{}
	form.Set("csrf_token", srv.CSRFToken())
	form.Set("ID.AM-01/documentation/inventaire", "defined")
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.ServeHTTP(httptest.NewRecorder(), req)

	first := srv.Responses()
	first["ID.AM-01/documentation/inventaire"] = "TRAFIQUÉ"

	second := srv.Responses()
	if second["ID.AM-01/documentation/inventaire"] != "defined" {
		t.Errorf("Responses() ne renvoie pas une copie : l'état interne a été muté")
	}
}

// post envoie une soumission avec les en-têtes donnés.
func post(srv *Server, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8099/submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// Le formulaire embarque le jeton anti-CSRF, propre à chaque démarrage.
func TestFormContientJeton(t *testing.T) {
	srv := New(testQuestions())
	if len(srv.CSRFToken()) != 64 || New(testQuestions()).CSRFToken() == srv.CSRFToken() {
		t.Fatalf("jeton anti-CSRF absent ou non aléatoire : %q", srv.CSRFToken())
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rec.Body.String(), `name="csrf_token" value="`+srv.CSRFToken()+`"`) {
		t.Error("le formulaire ne contient pas le jeton anti-CSRF")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("en-têtes anti-clickjacking absents")
	}
}

func TestPostRefuseSansJetonValide(t *testing.T) {
	for name, token := range map[string]string{"absent": "", "faux": strings.Repeat("0", 64)} {
		t.Run(name, func(t *testing.T) {
			srv := New(testQuestions())
			called := false
			srv.OnSubmit = func(survey.Responses) error { called = true; return nil }
			form := url.Values{}
			if token != "" {
				form.Set("csrf_token", token)
			}
			form.Set("ID.AM-01/documentation/inventaire", "defined")
			if rec := post(srv, form, nil); rec.Code != http.StatusForbidden {
				t.Fatalf("code %d, 403 attendu", rec.Code)
			}
			if srv.Responses() != nil || called {
				t.Error("une soumission sans jeton valide a été enregistrée")
			}
		})
	}
}

func TestPostRefuseOrigineEtrangere(t *testing.T) {
	cases := map[string]map[string]string{
		"origin tierce": {"Origin": "https://evil.example"},
		"referer tiers": {"Referer": "https://evil.example/page"},
		"origin opaque": {"Origin": "null"},
		"autre port":    {"Origin": "http://127.0.0.1:9999"},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := New(testQuestions())
			form := url.Values{"csrf_token": {srv.CSRFToken()}}
			if rec := post(srv, form, h); rec.Code != http.StatusForbidden {
				t.Errorf("code %d, 403 attendu", rec.Code)
			}
		})
	}
	srv := New(testQuestions())
	form := url.Values{"csrf_token": {srv.CSRFToken()}}
	if rec := post(srv, form, map[string]string{"Origin": "http://127.0.0.1:8099"}); rec.Code != http.StatusOK {
		t.Errorf("même origine refusée : code %d", rec.Code)
	}
}

// Anti DNS rebinding : un nom d'hôte étranger qui pointerait vers 127.0.0.1
// est refusé, en lecture comme en écriture.
func TestHoteNonAutorise(t *testing.T) {
	srv := New(testQuestions())
	srv.AllowedHosts = []string{"127.0.0.1:8099", "localhost:8099"}
	req := httptest.NewRequest(http.MethodGet, "http://rebind.evil.example:8099/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("hôte étranger accepté : code %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "http://localhost:8099/", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("hôte local refusé : code %d", rec.Code)
	}
}

func TestOnSubmitRecoitLesReponses(t *testing.T) {
	srv := New(testQuestions())
	var got survey.Responses
	srv.OnSubmit = func(r survey.Responses) error { got = r; return nil }
	form := url.Values{"csrf_token": {srv.CSRFToken()}, "ID.AM-01/documentation/inventaire": {"defined"}}
	if rec := post(srv, form, nil); rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	if got["ID.AM-01/documentation/inventaire"] != "defined" {
		t.Errorf("OnSubmit n'a pas reçu la réponse : %v", got)
	}
	srv.OnSubmit = func(survey.Responses) error { return errors.New("disque plein") }
	if rec := post(srv, form, nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("échec d'enregistrement non signalé : code %d", rec.Code)
	}
}

func TestTitreAfficheLeNiveau(t *testing.T) {
	srv := New(testQuestions())
	srv.Level = "Important"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rec.Body.String(), "niveau Important") || !strings.Contains(rec.Body.String(), "2 questions") {
		t.Error("le niveau ou le nombre de questions n'apparaît pas dans la page")
	}
}
