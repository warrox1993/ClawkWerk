// Package session assemble le résultat d'un audit en une enveloppe unique,
// calcule la conformité selon les seuils officiels CyFun Basic, et la
// sérialise en JSON — le format de sortie intermédiaire consommé ensuite par
// le générateur de rapport. Compatible stateless : rien n'est écrit sur la
// clé, l'enveloppe vit en RAM et est exportée en fin de session.
package session

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

const schemaVersion = "1.0"

// Disclaimer légal obligatoire, présent dans toute sortie (cf. positionnement
// « préparateur à la conformité », pas organisme de certification).
const Disclaimer = "Auto-évaluation assistée — ne constitue ni une vérification (niveaux Basic et Important) ni une certification (niveau Essential) CyFun, ni une présomption de conformité NIS2 : celles-ci sont délivrées par un organisme d’évaluation de la conformité (CAB) accrédité par BELAC et autorisé par le CCB."

// NIS2Note situe l'auto-évaluation dans le dispositif belge NIS2 (annexe
// légale des rapports). Source : CCB, https://atwork.safeonweb.be/nis2
// (page consultée le 28/09/2026) ; seuls la loi du 26 avril 2024 et l'arrêté
// royal du 9 juin 2024 publiés au Moniteur belge font foi.
const NIS2Note = "Cadre NIS2 (Belgique) : loi du 26 avril 2024 et arrêté royal du 9 juin 2024. Le CCB recommande le référentiel CyberFundamentals (CyFun) pour mettre en œuvre les mesures de gestion des risques ; une entité essentielle bénéficie d'une présomption de conformité après une vérification ou certification CyFun, ou une certification ISO/IEC 27001, délivrée par un CAB accrédité et autorisé par le CCB, ou fait l'objet d'une inspection du CCB. Une auto-évaluation comme celle-ci sert à préparer ces démarches ; elle n'en tient pas lieu. Source : CCB, atwork.safeonweb.be/nis2."

// Framework identifie le référentiel et le niveau audités.
type Framework struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Level   string `json:"level"`
}

// ConformitySummary = verdict de conformité pour un niveau donné.
type ConformitySummary struct {
	Level                 string              `json:"level"`
	TotalMaturity         cyfun.MaturityScore `json:"total_maturity"`
	TotalThreshold        cyfun.MaturityScore `json:"total_threshold"`
	KeyMeasureThreshold   cyfun.MaturityScore `json:"key_measure_threshold"`
	KeyMeasuresConform    bool                `json:"key_measures_conform"`
	NonConformKeyMeasures []string            `json:"non_conform_key_measures,omitempty"`
	CategoryThreshold     cyfun.MaturityScore `json:"category_threshold"` // 0 = n/a (Basic, Important)
	CategoriesConform     bool                `json:"categories_conform"`
	NonConformCategories  []string            `json:"non_conform_categories,omitempty"`

	// Incomplete = au moins un contrôle n'a pu être évalué (ni scan, ni
	// attestation de repli, ni N/A). Tant que des trous subsistent, AUCUN verdict
	// de conformité n'est délivré : Conform reste faux et le rapport affiche
	// « AUDIT INCOMPLET — N contrôles à évaluer ». Les contrôles concernés ne sont
	// PAS notés 0 (ce serait une fausse faille) : ils sont exclus de la moyenne et
	// listés ici comme à compléter.
	// Categories = « Category Maturity Overview » de l'onglet Summary de l'outil
	// officiel : pour chaque catégorie, maturités Documentation et
	// Implementation (moyennes des sous-catégories) et leur moyenne.
	Categories []CategoryScore `json:"categories,omitempty"`

	Incomplete         bool     `json:"incomplete"`
	UnassessedControls []string `json:"unassessed_controls,omitempty"`

	Conform bool `json:"conform"`
}

// CategoryScore = une ligne du « Category Maturity Overview » officiel.
type CategoryScore struct {
	Category       string              `json:"category"`
	Function       string              `json:"function"`
	Documentation  cyfun.MaturityScore `json:"documentation_maturity"`
	Implementation cyfun.MaturityScore `json:"implementation_maturity"`
	Maturity       cyfun.MaturityScore `json:"maturity"`
}

// ComputeConformity applique les règles officielles du NIVEAU demandé : conforme
// si la maturité totale moyenne ≥ seuil ET chaque Key Measure ≥ seuil. Seuils :
// Basic 2,5/5 ; Important 3/5 ; Essential 3,5/5.
func ComputeConformity(results []assess.ControlResult, level string) ConformitySummary {
	km, cat, total := cyfun.Thresholds(level)
	s := ConformitySummary{
		Level:               level,
		TotalThreshold:      total,
		KeyMeasureThreshold: km,
		CategoryThreshold:   cat,
		KeyMeasuresConform:  true,
		CategoriesConform:   true,
	}
	if len(results) == 0 {
		return s
	}

	// COMPLÉTUDE : on sépare les contrôles ÉVALUÉS (scan, attestation de repli ou
	// N/A) des contrôles NON évalués. Ces derniers ne sont JAMAIS notés 0 (ce serait
	// une fausse faille) : ils sont exclus de tous les calculs et bloqueront le
	// verdict tant qu'ils ne sont pas résolus (scan, questionnaire ou override).
	assessed := make([]assess.ControlResult, 0, len(results))
	for _, r := range results {
		if r.Assessed() {
			assessed = append(assessed, r)
		} else {
			s.Incomplete = true
			s.UnassessedControls = append(s.UnassessedControls, r.Meta.ID)
		}
	}

	// Key Measures : maturité du requirement = moyenne(Doc, Impl) ≥ seuil KM.
	// Un Key Measure marqué N/A prend la valeur du seuil (barème CCB) → conforme.
	// Un KM NON évalué n'est pas « non conforme » : il est déjà listé comme à
	// évaluer et bloque le verdict via Incomplete.
	for _, r := range assessed {
		if r.Meta.KeyMeasure && !r.NotApplicable && !r.ConformAt(km) {
			s.KeyMeasuresConform = false
			s.NonConformKeyMeasures = append(s.NonConformKeyMeasures, r.Meta.ID)
		}
	}

	// Agrégation HIÉRARCHIQUE, à l'identique du barème officiel CCB, SUR LES
	// CONTRÔLES ÉVALUÉS. Un contrôle N/A prend la valeur du seuil KM (naValue),
	// comme la substitution du xlsx. Quand l'audit est COMPLET, assessed == results
	// et l'agrégation est rigoureusement identique (parité CCB préservée).
	totalMat, catMat, catAxes := aggregateAxes(assessed, km)
	s.TotalMaturity = totalMat
	s.Categories = catAxes

	// Seuil par CATÉGORIE (Essential : cat > 0), sur la Category Maturity Score.
	if cat > 0 {
		cats := make([]string, 0, len(catMat))
		for c := range catMat {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			if catMat[c] < cat {
				s.CategoriesConform = false
				s.NonConformCategories = append(s.NonConformCategories, c)
			}
		}
	}

	// Verdict BLOQUÉ tant qu'il subsiste des trous : aucun conforme/non-conforme
	// n'est délivré si l'audit est incomplet — la complétude prime sur le score.
	s.Conform = !s.Incomplete && s.TotalMaturity >= total && s.KeyMeasuresConform && s.CategoriesConform
	return s
}

// aggregateAxes reproduit EXACTEMENT le calcul de maturité du barème officiel CCB
// (formules Excel des feuilles de fonction + onglet Summary) :
//
//	requirement --moyenne--> sous-catégorie --moyenne--> catégorie --moyenne--> total
//
// Documentation et Implementation sont agrégées SÉPARÉMENT le long de la
// hiérarchie, puis combinées au niveau CATÉGORIE :
//
//	Category Maturity = moyenne(Category Doc Maturity, Category Impl Maturity)
//	Total Maturity    = moyenne des Category Maturity
//
// Chaque étage pèse également (moyenne de moyennes), donc une catégorie riche en
// contrôles ne pèse pas plus qu'une autre — d'où l'écart avec une moyenne à plat.
// Renvoie la maturité totale et la Category Maturity Score par catégorie.
// Il renvoie aussi, par catégorie (dans l'ordre des fonctions), les
// maturités Documentation et Implementation, comme l'onglet Summary.
func aggregateAxes(results []assess.ControlResult, naValue cyfun.MaturityScore) (total cyfun.MaturityScore, catMaturity map[string]cyfun.MaturityScore, cats []CategoryScore) {
	type acc struct {
		doc, impl cyfun.MaturityScore
		n         int
	}
	// Étage 1 : sous-catégorie = moyenne des requirements (Doc et Impl séparés).
	// Clé COMPOSITE catégorie/sous-catégorie (les sous-catégories réelles sont
	// uniques, ex. "GV.OC-01", mais on ne s'y fie pas).
	sub := map[string]*acc{}
	subCat := map[string]string{} // clé composite -> catégorie
	for _, r := range results {
		key := r.Meta.Category + "\x00" + r.Meta.Subcategory
		a := sub[key]
		if a == nil {
			a = &acc{}
			sub[key] = a
			subCat[key] = r.Meta.Category
		}
		// Substitution N/A : comme le xlsx CCB, un contrôle non applicable prend
		// la valeur du seuil (Doc et Impl), donc il ne pèse ni pour ni contre.
		if r.NotApplicable {
			a.doc += naValue
			a.impl += naValue
		} else {
			a.doc += cyfun.MaturityScore(r.FinalDoc)
			a.impl += cyfun.MaturityScore(r.FinalImpl)
		}
		a.n++
	}
	// Étage 2 : catégorie = moyenne des sous-catégories.
	cat := map[string]*acc{}
	catFunc := map[string]string{}
	for _, r := range results {
		catFunc[r.Meta.Category] = string(r.Meta.Function)
	}
	for subID, a := range sub {
		c := cat[subCat[subID]]
		if c == nil {
			c = &acc{}
			cat[subCat[subID]] = c
		}
		c.doc += a.doc / cyfun.MaturityScore(a.n)   // moyenne Doc de la sous-catégorie
		c.impl += a.impl / cyfun.MaturityScore(a.n) // moyenne Impl de la sous-catégorie
		c.n++
	}
	// Étage 3 : Category Maturity = moyenne(CatDoc, CatImpl) ; Total = moyenne.
	catMaturity = make(map[string]cyfun.MaturityScore, len(cat))
	var totSum cyfun.MaturityScore
	for id, c := range cat {
		catDoc := c.doc / cyfun.MaturityScore(c.n)
		catImpl := c.impl / cyfun.MaturityScore(c.n)
		m := (catDoc + catImpl) / 2
		catMaturity[id] = m
		totSum += m
		cats = append(cats, CategoryScore{Category: id, Function: catFunc[id], Documentation: catDoc, Implementation: catImpl, Maturity: m})
	}
	sort.Slice(cats, func(i, j int) bool {
		fi, fj := functionRank[cats[i].Function], functionRank[cats[j].Function]
		if fi != fj {
			return fi < fj
		}
		return cats[i].Category < cats[j].Category
	})
	if len(cat) > 0 {
		total = totSum / cyfun.MaturityScore(len(cat))
	}
	return total, catMaturity, cats
}

// functionRank ordonne les fonctions comme le référentiel (GV, ID, PR, DE, RS, RC).
var functionRank = map[string]int{"GOVERN": 1, "IDENTIFY": 2, "PROTECT": 3, "DETECT": 4, "RESPOND": 5, "RECOVER": 6}

// AuditSession = enveloppe complète d'une session d'audit.
type AuditSession struct {
	SchemaVersion string                 `json:"schema_version"`
	SessionID     string                 `json:"session_id"`
	Framework     Framework              `json:"framework"`
	Scope         scope.AuditScope       `json:"scope"`
	StartedAt     time.Time              `json:"started_at"`
	ExportedAt    time.Time              `json:"exported_at"`
	Results       []assess.ControlResult `json:"results"`
	Journal       []audit.Entry          `json:"journal"`
	Conformity    ConformitySummary      `json:"conformity"`
	Disclaimer    string                 `json:"disclaimer"`
}

// New assemble une session au niveau Basic (raccourci de compatibilité).
func New(sessionID string, sc scope.AuditScope, results []assess.ControlResult, journal []audit.Entry, startedAt, exportedAt time.Time) AuditSession {
	return NewAtLevel(sessionID, cyfun.LevelBasic, sc, results, journal, startedAt, exportedAt)
}

// NewAtLevel assemble une session pour un NIVEAU d'assurance donné (Basic /
// Important / Essential) : calcule la conformité au bon seuil, fige le schéma et
// le disclaimer. Les horodatages sont passés par l'appelant (testabilité).
func NewAtLevel(sessionID, level string, sc scope.AuditScope, results []assess.ControlResult, journal []audit.Entry, startedAt, exportedAt time.Time) AuditSession {
	return AuditSession{
		SchemaVersion: schemaVersion,
		SessionID:     sessionID,
		Framework:     Framework{Name: "CyFun", Version: "2025", Level: level},
		Scope:         sc,
		StartedAt:     startedAt,
		ExportedAt:    exportedAt,
		Results:       results,
		Journal:       journal,
		Conformity:    ComputeConformity(results, level),
		Disclaimer:    Disclaimer,
	}
}

// ToJSON sérialise l'enveloppe en JSON indenté (inspectable = preuve d'audit).
func (s AuditSession) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}
