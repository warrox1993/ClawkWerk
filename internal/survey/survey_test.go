package survey

import (
	"reflect"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// catalogue de test : un contrôle scannable (Documentation seule) et un
// contrôle déclaratif (Documentation + Implementation).
func testQuestions() []Question {
	yesNo := func(id, ctrl string, axis Axis, text string) Question {
		return Question{
			ID: id, ControlID: ctrl, Axis: axis, Text: text,
			Choices: []Choice{
				{Key: "no", Label: "Non", Level: cyfun.Initial},
				{Key: "partial", Label: "Partiellement", Level: cyfun.Repeatable},
				{Key: "yes", Label: "Oui, formalisé", Level: cyfun.Defined},
			},
		}
	}
	return []Question{
		yesNo("DE.CM-01.2/documentation/policy", "DE.CM-01.2", Documentation, "Politique AV écrite ?"),
		yesNo("DE.CM-01.2/documentation/review", "DE.CM-01.2", Documentation, "Revue < 2 ans ?"),
		yesNo("GV.PO-01.1/documentation/policy", "GV.PO-01.1", Documentation, "Politique SSI écrite ?"),
		yesNo("GV.PO-01.1/implementation/applied", "GV.PO-01.1", Implementation, "Politique appliquée ?"),
	}
}

func TestScore_WeakestLinkAcrossQuestions(t *testing.T) {
	q := New(testQuestions(), nil)
	r := Responses{
		"DE.CM-01.2/documentation/policy": "yes",     // Defined (3)
		"DE.CM-01.2/documentation/review": "partial", // Repeatable (2) => maillon faible
	}
	if got := q.Score("DE.CM-01.2", Documentation, r); got != cyfun.Repeatable {
		t.Fatalf("maillon faible attendu Repeatable(2), obtenu %d", got)
	}
}

func TestScore_UnansweredQuestionCapsToNotAssessed(t *testing.T) {
	q := New(testQuestions(), nil)
	r := Responses{
		"DE.CM-01.2/documentation/policy": "yes", // l'autre question reste sans réponse
	}
	if got := q.Score("DE.CM-01.2", Documentation, r); got != cyfun.NotAssessed {
		t.Fatalf("question non répondue => NotAssessed(0), obtenu %d", got)
	}
}

func TestScore_UnknownChoiceKeyTreatedAsUnanswered(t *testing.T) {
	q := New(testQuestions(), nil)
	r := Responses{
		"DE.CM-01.2/documentation/policy": "bidon",
		"DE.CM-01.2/documentation/review": "yes",
	}
	if got := q.Score("DE.CM-01.2", Documentation, r); got != cyfun.NotAssessed {
		t.Fatalf("clé inconnue => NotAssessed(0), obtenu %d", got)
	}
}

func TestScore_NoQuestionForAxisIsNotAssessed(t *testing.T) {
	q := New(testQuestions(), nil)
	// DE.CM-01.2 n'a aucune question Implementation (contrôle scannable).
	if got := q.Score("DE.CM-01.2", Implementation, Responses{}); got != cyfun.NotAssessed {
		t.Fatalf("axe sans question => NotAssessed, obtenu %d", got)
	}
}

func TestScoreMap_DocumentationCoversAllControlsWithDocQuestions(t *testing.T) {
	q := New(testQuestions(), nil)
	r := Responses{
		"DE.CM-01.2/documentation/policy":   "yes",
		"DE.CM-01.2/documentation/review":   "yes",
		"GV.PO-01.1/documentation/policy":   "partial",
		"GV.PO-01.1/implementation/applied": "yes",
	}
	doc := q.ScoreMap(Documentation, r)
	want := map[string]cyfun.MaturityLevel{
		"DE.CM-01.2": cyfun.Defined,    // yes+yes
		"GV.PO-01.1": cyfun.Repeatable, // partial
	}
	if !reflect.DeepEqual(doc, want) {
		t.Fatalf("DocScores inattendus:\n got  %v\n want %v", doc, want)
	}
}

func TestScoreMap_ImplementationOnlyForDeclarativeControls(t *testing.T) {
	q := New(testQuestions(), nil)
	r := Responses{"GV.PO-01.1/implementation/applied": "yes"}
	impl := q.ScoreMap(Implementation, r)
	// Seul GV.PO-01.1 a une question Implementation ; DE.CM-01.2 n'y figure pas.
	if _, present := impl["DE.CM-01.2"]; present {
		t.Fatalf("un contrôle scannable ne doit pas recevoir d'Impl du questionnaire: %v", impl)
	}
	if impl["GV.PO-01.1"] != cyfun.Defined {
		t.Fatalf("Impl GV.PO-01.1 attendu Defined(3), obtenu %d", impl["GV.PO-01.1"])
	}
}

func TestUnanswered_ListsMissingSorted(t *testing.T) {
	q := New(testQuestions(), nil)
	r := Responses{
		"DE.CM-01.2/documentation/policy":   "yes",
		"GV.PO-01.1/implementation/applied": "zzz", // clé inconnue = non répondue
	}
	got := q.Unanswered(r)
	want := []string{
		"DE.CM-01.2/documentation/review",
		"GV.PO-01.1/documentation/policy",
		"GV.PO-01.1/implementation/applied",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Unanswered:\n got  %v\n want %v", got, want)
	}
}

func TestScore_CustomCombinerOverridesDefault(t *testing.T) {
	// combineur "moyenne plancher" pour prouver la surcharge par contrôle.
	avg := func(levels []cyfun.MaturityLevel) cyfun.MaturityLevel {
		var sum int
		for _, l := range levels {
			sum += int(l)
		}
		return cyfun.MaturityLevel(sum / len(levels))
	}
	q := New(testQuestions(), map[string]Combine{"DE.CM-01.2": avg})
	r := Responses{
		"DE.CM-01.2/documentation/policy": "yes",     // 3
		"DE.CM-01.2/documentation/review": "partial", // 2  => moyenne plancher = 2
	}
	if got := q.Score("DE.CM-01.2", Documentation, r); got != cyfun.Repeatable {
		t.Fatalf("combineur surchargé attendu 2, obtenu %d", got)
	}
}
