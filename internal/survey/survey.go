// Package survey modélise le questionnaire déclaratif de CyFun : les contrôles
// organisationnels (procédures, politiques, gouvernance) ne se scannent pas,
// ils se constatent par entretien. Le questionnaire alimente l'axe
// Documentation de TOUS les contrôles, et l'axe Implementation des seuls
// contrôles déclaratifs (les contrôles scannables tirent leur Implementation
// du scan — séparation stricte des sources, décidée en session 1).
//
// Patron réutilisé des Evaluators : des FAITS (ici les réponses du consultant)
// passent dans une FONCTION PURE qui rend un cyfun.MaturityLevel. Aucune I/O,
// déterministe, testable en TDD.
package survey

import (
	"sort"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// Axis désigne l'axe de notation qu'une question alimente.
//
// Pourquoi un type string nommé plutôt qu'un bool "isDoc" (réflexe C#) : la
// valeur est lisible telle quelle dans le JSON du questionnaire exporté, et on
// pourrait ajouter un 3e axe plus tard sans casser la signature.
type Axis string

const (
	Documentation  Axis = "documentation"  // règles/procédures écrites
	Implementation Axis = "implementation" // pratique opérationnelle réelle
)

// Choice = une réponse sélectionnable et le niveau de maturité qu'elle
// implique pour l'axe de sa question. Key est la valeur stable postée par le
// formulaire ; Label est le texte affiché.
type Choice struct {
	Key   string              `json:"key"`   // "yes" | "partial" | "no" ...
	Label string              `json:"label"` // texte lisible pour l'UI web
	Level cyfun.MaturityLevel `json:"level"` // maturité impliquée par ce choix
}

// Question = un item du questionnaire, rattaché à un contrôle et un axe.
// ID est stable et unique (il sert de clé de réponse) ; convention :
// "<controlID>/<axe>/<slug>", ex. "DE.CM-01.2/documentation/policy".
type Question struct {
	ID        string   `json:"id"`
	ControlID string   `json:"control_id"`
	Axis      Axis     `json:"axis"`
	Text      string   `json:"text"`
	Choices   []Choice `json:"choices"`
}

// StdChoices renvoie l'échelle de maturité standard réutilisable, alignée sur
// le barème officiel CyFun (1..5). La plupart des questions déclaratives
// partagent cette échelle ; un contrôle atypique peut fournir ses propres
// Choices. Le niveau 5 (Optimizing) suppose amélioration continue + métriques :
// à ne cocher qu'avec preuve, d'où son libellé exigeant.
func StdChoices() []Choice {
	return []Choice{
		{Key: "none", Label: "Inexistant / non formalisé", Level: cyfun.Initial},
		{Key: "adhoc", Label: "Informel, ad hoc (ou doc non revue >2 ans)", Level: cyfun.Repeatable},
		{Key: "defined", Label: "Formalisé, approuvé et appliqué", Level: cyfun.Defined},
		{Key: "managed", Label: "Formalisé + mesuré (métriques, revues régulières)", Level: cyfun.Managed},
		{Key: "optimizing", Label: "Amélioration continue démontrée (preuves)", Level: cyfun.Optimizing},
	}
}

// Ask construit une question sur l'échelle standard. Réduit le bruit dans les
// fichiers de contrôle : Ask("DE.CM-01.2", Documentation, "policy", "…").
func Ask(controlID string, axis Axis, slug, text string) Question {
	return Question{
		ID:        controlID + "/" + string(axis) + "/" + slug,
		ControlID: controlID,
		Axis:      axis,
		Text:      text,
		Choices:   StdChoices(),
	}
}

// levelFor renvoie le niveau associé à la réponse choisie, et false si la
// question est sans réponse ou si la clé postée est inconnue (formulaire
// incomplet ou trafiqué). L'appelant décide alors quoi faire du trou.
func (q Question) levelFor(answer string) (cyfun.MaturityLevel, bool) {
	for _, c := range q.Choices {
		if c.Key == answer {
			return c.Level, true
		}
	}
	return cyfun.NotAssessed, false
}

// Responses = questionnaire rempli : ID de question -> clé de la réponse
// choisie. C'est exactement la forme d'un POST de formulaire web.
type Responses map[string]string

// Combine réduit les niveaux des questions d'un même contrôle+axe en un seul
// niveau. Le défaut est WeakestLink ; un contrôle peut fournir le sien.
type Combine func([]cyfun.MaturityLevel) cyfun.MaturityLevel

// WeakestLink retient le niveau le plus faible : cohérent avec assess.WorstCase
// et avec la posture "ne jamais surestimer la maturité". Une seule question
// laissée sans réponse rabaisse donc l'axe à NotAssessed (0) — c'est
// volontaire : un questionnaire incomplet n'est pas scoré, il est signalé.
func WeakestLink(levels []cyfun.MaturityLevel) cyfun.MaturityLevel {
	if len(levels) == 0 {
		return cyfun.NotAssessed
	}
	worst := levels[0]
	for _, l := range levels[1:] {
		if l < worst {
			worst = l
		}
	}
	return worst
}

// Questionnaire = catalogue des questions d'un audit, indexé pour le rendu et
// le scoring. On le construit une fois via New à partir des questions déclarées
// près de chaque contrôle.
type Questionnaire struct {
	questions []Question
	byControl map[string][]Question // controlID -> ses questions (ordre stable)
	combiners map[string]Combine    // controlID -> combineur (défaut WeakestLink)
}

// New indexe une liste plate de questions. combiners est optionnel (nil = tout
// en WeakestLink). L'ordre des questions par contrôle est préservé pour un
// rendu de formulaire stable.
func New(questions []Question, combiners map[string]Combine) *Questionnaire {
	q := &Questionnaire{
		questions: questions,
		byControl: make(map[string][]Question),
		combiners: combiners,
	}
	for _, item := range questions {
		q.byControl[item.ControlID] = append(q.byControl[item.ControlID], item)
	}
	return q
}

// For renvoie les questions d'un contrôle (pour rendre le formulaire web).
func (q *Questionnaire) For(controlID string) []Question {
	return q.byControl[controlID]
}

// Questions renvoie toutes les questions (rendu global du questionnaire).
func (q *Questionnaire) Questions() []Question {
	return q.questions
}

// combineFor choisit le combineur d'un contrôle (défaut WeakestLink).
func (q *Questionnaire) combineFor(controlID string) Combine {
	if c, ok := q.combiners[controlID]; ok && c != nil {
		return c
	}
	return WeakestLink
}

// Score calcule le niveau de maturité d'un contrôle sur un axe donné à partir
// des réponses. Une question sans réponse (ou à clé inconnue) compte comme
// NotAssessed : avec WeakestLink, cela rabaisse l'axe — le trou est visible,
// pas masqué. Renvoie NotAssessed si le contrôle n'a aucune question sur l'axe.
func (q *Questionnaire) Score(controlID string, axis Axis, r Responses) cyfun.MaturityLevel {
	var levels []cyfun.MaturityLevel
	for _, item := range q.byControl[controlID] {
		if item.Axis != axis {
			continue
		}
		lvl, _ := item.levelFor(r[item.ID]) // false => NotAssessed, ce qui est correct
		levels = append(levels, lvl)
	}
	if len(levels) == 0 {
		return cyfun.NotAssessed
	}
	return q.combineFor(controlID)(levels)
}

// ScoreMap projette les réponses en une map controlID -> niveau sur un axe,
// pour tous les contrôles ayant au moins une question sur cet axe. C'est ce
// que consomme l'orchestrateur : DocScores (axe Documentation, tous contrôles)
// et ImplScores (axe Implementation, contrôles déclaratifs uniquement).
func (q *Questionnaire) ScoreMap(axis Axis, r Responses) map[string]cyfun.MaturityLevel {
	out := make(map[string]cyfun.MaturityLevel)
	for controlID := range q.byControl {
		if !q.hasAxis(controlID, axis) {
			continue
		}
		out[controlID] = q.Score(controlID, axis, r)
	}
	return out
}

// hasAxis indique si un contrôle possède au moins une question sur l'axe.
func (q *Questionnaire) hasAxis(controlID string, axis Axis) bool {
	for _, item := range q.byControl[controlID] {
		if item.Axis == axis {
			return true
		}
	}
	return false
}

// Unanswered renvoie, triés, les ID des questions du catalogue sans réponse
// exploitable — pour signaler au consultant ce qu'il reste à remplir avant de
// figer l'audit (le questionnaire incomplet est la première cause de score bas
// injustifié).
func (q *Questionnaire) Unanswered(r Responses) []string {
	var missing []string
	for _, item := range q.questions {
		if _, ok := item.levelFor(r[item.ID]); !ok {
			missing = append(missing, item.ID)
		}
	}
	sort.Strings(missing)
	return missing
}
