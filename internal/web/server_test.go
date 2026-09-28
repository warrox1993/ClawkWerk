package web

import (
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
