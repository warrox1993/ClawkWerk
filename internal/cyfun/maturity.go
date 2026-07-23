// Package cyfun contient les types du référentiel CyberFundamentals (CyFun)
// et le barème de maturité officiel du CCB. Il ne dépend d'aucun autre
// paquet du projet : c'est le socle de domaine.
package cyfun

// MaturityLevel est une note ENTIÈRE 1..5 saisie par requirement, sur l'axe
// Documentation OU Implementation. 0 = non évalué.
//
// Pourquoi un type nommé plutôt qu'un int nu (réflexe Java/C#) : en Go, un
// type distinct empêche de mélanger accidentellement un niveau (entier) avec
// un score agrégé (décimal, voir MaturityScore), et permet d'attacher des
// méthodes et des constantes parlantes.
type MaturityLevel int

const (
	NotAssessed MaturityLevel = 0 // pas de preuve exploitable
	Initial     MaturityLevel = 1 // pas de doc / processus inexistant
	Repeatable  MaturityLevel = 2 // doc non revue depuis 2 ans / ad hoc informel
	Defined     MaturityLevel = 3 // doc approuvée <5% except. / processus formel <10% except.
	Managed     MaturityLevel = 4 // exceptions <3% / métriques capturées <5% except.
	Optimizing  MaturityLevel = 5 // exceptions <0,5% / amélioration continue <1% except.
)

// MaturityScore est un score AGRÉGÉ, décimal (moyennes de requirements,
// de sous-catégories, etc.). Les seuils de conformité s'expriment ici
// (ex. 2,5) — d'où la nécessité d'un flottant, distinct de MaturityLevel.
type MaturityScore float64

// MaturityRubric = texte officiel des 5 niveaux (source : onglet
// « Maturity Levels » du Self-Assessment tool BASIC du CCB). Isolé ici comme
// DONNÉE : le jour où l'on obtient une formulation officielle différente, on
// édite cette table sans toucher aux évaluateurs de contrôles.
var MaturityRubric = map[MaturityLevel]string{
	Initial:    "Initial — pas de documentation / le processus standard n'existe pas.",
	Repeatable: "Repeatable — doc approuvée mais non revue depuis 2 ans ; processus ad hoc informel.",
	Defined:    "Defined — doc approuvée, exceptions <5% ; processus formel implémenté, preuves, <10% d'exceptions.",
	Managed:    "Managed — exceptions <3% ; métriques capturées et cible définie, <5% d'exceptions.",
	Optimizing: "Optimizing — exceptions <0,5% ; amélioration continue, <1% d'exceptions.",
}

// Seuils de conformité OFFICIELS au niveau BASIC (source : onglet
// « Maturity Levels », colonne « Maturity level thresholds BASIC »).
const (
	BasicKeyMeasureThreshold MaturityScore = 2.5 // chaque Key Measure : moyenne(Doc,Impl) ≥ 2,5
	BasicTotalThreshold      MaturityScore = 2.5 // maturité totale moyenne ≥ 2,5
)

// Niveaux d'assurance CyFun (ordonnés). Un contrôle « Basic » s'audite aussi à
// Important et Essential (Important est un SUR-ENSEMBLE de Basic) ; un contrôle
// « Important » ne s'audite qu'à partir d'Important.
const (
	LevelBasic     = "Basic"
	LevelImportant = "Important"
	LevelEssential = "Essential"
)

// rang d'un niveau pour les comparaisons (Basic < Important < Essential).
var levelRank = map[string]int{LevelBasic: 1, LevelImportant: 2, LevelEssential: 3}

// levelThreshold = seuils OFFICIELS d'un niveau (onglet « Maturity Levels » de
// chaque outil CCB) : chaque Key Measure, chaque Catégorie (0 = n/a), et la
// maturité totale. Ils ne sont PAS uniformes — d'où trois valeurs :
//   - Basic     : KM ≥ 2,5 ; catégorie n/a ; total ≥ 2,5
//   - Important : KM ≥ 3   ; catégorie n/a ; total ≥ 3
//   - Essential : KM ≥ 3   ; catégorie ≥ 3 ; total ≥ 3,5
type levelThreshold struct{ KM, Cat, Total MaturityScore }

var levelThresholds = map[string]levelThreshold{
	LevelBasic:     {KM: 2.5, Cat: 0, Total: 2.5},
	LevelImportant: {KM: 3.0, Cat: 0, Total: 3.0},
	LevelEssential: {KM: 3.0, Cat: 3.0, Total: 3.5},
}

// Thresholds renvoie les seuils (Key Measure, Catégorie, Total) d'un niveau.
// Cat = 0 signifie « pas de seuil par catégorie ». Défaut Basic si inconnu.
func Thresholds(level string) (km, cat, total MaturityScore) {
	t, ok := levelThresholds[level]
	if !ok {
		t = levelThresholds[LevelBasic]
	}
	return t.KM, t.Cat, t.Total
}

// Threshold (compat) renvoie le seuil de maturité TOTALE d'un niveau.
func Threshold(level string) MaturityScore {
	_, _, total := Thresholds(level)
	return total
}

// AppliesAt indique si un contrôle de niveau minimal controlLevel entre dans le
// périmètre d'un audit mené au niveau auditLevel (Basic ⊂ Important ⊂ Essential).
func AppliesAt(controlLevel, auditLevel string) bool {
	cl, ok1 := levelRank[controlLevel]
	al, ok2 := levelRank[auditLevel]
	if !ok1 || !ok2 {
		return controlLevel == LevelBasic // par défaut, un contrôle Basic s'applique
	}
	return cl <= al
}
