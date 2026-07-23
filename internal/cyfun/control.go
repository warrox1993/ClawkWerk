package cyfun

// Function est l'une des 6 fonctions du NIST CSF 2.0, sur lesquelles CyFun
// est aligné.
type Function string

const (
	Govern   Function = "GOVERN"
	Identify Function = "IDENTIFY"
	Protect  Function = "PROTECT"
	Detect   Function = "DETECT"
	Respond  Function = "RESPOND"
	Recover  Function = "RECOVER"
)

// ControlMeta = métadonnées statiques d'un contrôle CyFun. La forme est
// IDENTIQUE pour les 34 requirements du niveau Basic ; seul le contenu change.
//
// Hiérarchie officielle à 3 niveaux : Category (DE.CM) > Subcategory
// (DE.CM-01) > Requirement (DE.CM-01.2). C'est le Requirement qui est scoré,
// donc ID == identifiant du requirement.
type ControlMeta struct {
	ID          string   `json:"id"`          // "DE.CM-01.2" (= Requirement)
	Function    Function `json:"function"`    // Detect
	Category    string   `json:"category"`    // "DE.CM"
	Subcategory string   `json:"subcategory"` // "DE.CM-01"
	Requirement string   `json:"requirement"` // texte EXACT du référentiel (repris tel quel au rapport)
	Level       string   `json:"level"`       // "Basic"
	KeyMeasure  bool     `json:"key_measure"` // true => soumis au seuil individuel ≥ 2,5 au niveau Basic
}
