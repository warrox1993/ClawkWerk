package controls

import (
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// GV.PO-01.1 est un contrôle DÉCLARATIF (gouvernance) : il ne se scanne pas.
// Sa maturité vient entièrement du questionnaire, sur les DEUX axes —
// Documentation (la politique existe-t-elle, est-elle approuvée/revue) et
// Implementation (est-elle communiquée et appliquée dans les faits).
//
// C'est le patron des ~21 contrôles organisationnels du niveau Basic : un
// fichier Meta + Questions, sans Evaluator ni Commands. Le moteur le reconnaît
// comme déclaratif (Evaluator nil) et ne contacte aucun hôte.

// GVPO0101Meta : métadonnées officielles (texte exact du CCB, repris au rapport).
var GVPO0101Meta = cyfun.ControlMeta{
	ID:          "GV.PO-01.1",
	Function:    cyfun.Govern,
	Category:    "GV.PO",
	Subcategory: "GV.PO-01",
	Requirement: "Policies and procedures for managing information and cybersecurity shall be established, documented, reviewed, approved, updated when changes occur, communicated and enforced.",
	Level:       "Basic",
	KeyMeasure:  false,
}

// GVPO0101Questions : Documentation (existence/approbation/revue) +
// Implementation (communication/application effective).
var GVPO0101Questions = []survey.Question{
	survey.Ask("GV.PO-01.1", survey.Documentation, "established",
		"Des politiques et procédures de gestion de la sécurité de l'information sont-elles établies et documentées ?"),
	survey.Ask("GV.PO-01.1", survey.Documentation, "approved-reviewed",
		"Sont-elles approuvées par la direction, et revues/mises à jour lors de changements ?"),
	survey.Ask("GV.PO-01.1", survey.Implementation, "communicated",
		"Sont-elles communiquées à l'ensemble du personnel concerné ?"),
	survey.Ask("GV.PO-01.1", survey.Implementation, "enforced",
		"Sont-elles réellement appliquées et leur respect est-il contrôlé ?"),
}
