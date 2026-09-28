package report

import (
	"bytes"
	"fmt"

	"github.com/go-pdf/fpdf"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// PDF produit le rapport d'audit complet au format PDF, en s'appuyant sur
// github.com/go-pdf/fpdf — une bibliothèque PUR GO (aucun CGo), ce qui préserve
// la propriété « binaire statique unique » du projet. On reproduit la MÊME
// structure en 6 sections que le rapport HTML : synthèse, contexte, résultats
// détaillés, plan de remédiation, annexe technique, annexe légale.
//
// Pourquoi un rendu impératif plutôt qu'un template ? fpdf dessine des cellules
// positionnées (x, y) : on empile des blocs de haut en bas et la bibliothèque
// gère seule les sauts de page. Il n'y a pas de « template PDF » standard comme
// html/template ; on décrit donc le document pas à pas.
//
// Le rapport ne DÉCIDE de rien : il met en forme la View déjà calculée. Toute
// la logique de scoring/conformité reste en amont (cf. package session).
func PDF(v View) ([]byte, error) {
	// A4 portrait, unités en millimètres (naturel pour un document imprimable),
	// police par défaut Arial (une des polices « core » toujours disponibles,
	// donc aucun fichier de police à embarquer).
	pdf := fpdf.New("P", "mm", "A4", "")

	// Les polices core de fpdf sont encodées en Windows-1252 (cp1252), pas en
	// UTF-8. Nos textes français contiennent des accents (é, è, à, ç) et des
	// tirets cadratins (—) ; sans conversion ils s'afficheraient corrompus. Ce
	// « traducteur » convertit chaque chaîne UTF-8 vers cp1252 avant impression.
	tr := pdf.UnicodeTranslatorFromDescriptor("") // "" => cp1252 par défaut

	// Marges de 15 mm : largeur utile = 210 - 2*15 = 180 mm (base de nos tableaux).
	pdf.SetMargins(15, 15, 15)
	// Saut de page automatique déclenché à 15 mm du bas : fpdf ajoute une page
	// dès qu'une cellule déborderait. Indispensable pour de longs tableaux.
	pdf.SetAutoPageBreak(true, 15)
	pdf.AddPage()

	const contentW = 180.0 // largeur utile en mm, réutilisée partout

	// --- petites aides de mise en page (closures capturant pdf/tr) ---

	// title imprime un grand titre de document.
	title := func(s string) {
		pdf.SetFont("Arial", "B", 16)
		pdf.SetTextColor(0, 0, 0)
		pdf.MultiCell(contentW, 8, tr(s), "", "L", false)
	}
	// heading imprime un titre de section (équivalent des <h2> du HTML).
	heading := func(s string) {
		pdf.Ln(3)
		pdf.SetFont("Arial", "B", 13)
		pdf.SetTextColor(0, 0, 0)
		pdf.MultiCell(contentW, 7, tr(s), "B", "L", false) // bordure basse = filet sous le titre
		pdf.Ln(1)
	}
	// para imprime un paragraphe de texte courant qui se replie sur plusieurs
	// lignes (MultiCell gère les retours à la ligne automatiquement).
	para := func(s string) {
		pdf.SetFont("Arial", "", 10)
		pdf.SetTextColor(0, 0, 0)
		pdf.MultiCell(contentW, 5, tr(s), "", "L", false)
	}
	// banner imprime un encadré sur fond jaune pâle (les mentions légales du
	// HTML — classe .disclaimer). On dessine un fond puis le texte par-dessus.
	banner := func(s string) {
		pdf.SetFont("Arial", "", 9)
		pdf.SetTextColor(0, 0, 0)
		pdf.SetFillColor(255, 248, 225) // jaune très clair
		pdf.MultiCell(contentW, 5, tr(s), "1", "L", true)
		pdf.Ln(1)
	}
	// bullet imprime une puce de liste.
	bullet := func(s string) {
		pdf.SetFont("Arial", "", 10)
		pdf.SetTextColor(0, 0, 0)
		pdf.MultiCell(contentW, 5, tr("  - "+s), "", "L", false)
	}

	// --- Bandeau d'en-tête (comme le HTML : titre + méta + disclaimer) ---

	s := v.Session
	title("Rapport d'auto-évaluation CyFun — Niveau " + s.Framework.Level)
	pdf.SetFont("Arial", "", 10)
	pdf.MultiCell(contentW, 5, tr(fmt.Sprintf(
		"Client : %s\nRéférentiel : %s %s (aligné NIST CSF 2.0)\nSession : %s — exportée le %s",
		s.Scope.ClientRef, s.Framework.Name, s.Framework.Version,
		s.SessionID, s.ExportedAt.Format("2006-01-02 15:04"))), "", "L", false)
	pdf.Ln(2)
	// Disclaimer en tête (bandeau), exigé pour toute sortie du projet.
	banner(s.Disclaimer)

	// --- 1. Synthèse exécutive ---
	c := s.Conformity
	heading("1. Synthèse exécutive")
	// Audit incomplet : la complétude prime, aucun verdict de conformité délivré.
	if c.Incomplete {
		pdf.SetFont("Arial", "", 10)
		pdf.Write(5, tr("Verdict global : "))
		pdf.SetFont("Arial", "B", 10)
		pdf.SetTextColor(138, 109, 0) // ambre
		pdf.Write(5, tr(fmt.Sprintf("AUDIT INCOMPLET — %d controle(s) a evaluer", len(c.UnassessedControls))))
		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Arial", "", 10)
		pdf.Write(5, tr(fmt.Sprintf(" au niveau %s.", c.Level)))
		pdf.Ln(6)
		para("Aucun verdict de conformité n'est délivré tant que des contrôles ne sont pas " +
			"évalués (scan, questionnaire de repli, N/A attesté ou override consultant).")
		para(fmt.Sprintf("Maturité PARTIELLE (contrôles évalués seulement) : %s/5 (seuil requis : %s) — indicative.",
			score2(c.TotalMaturity), score2(c.TotalThreshold)))
		para("Contrôles à compléter :")
		for _, id := range c.UnassessedControls {
			bullet(id)
		}
	} else {
		pdf.SetFont("Arial", "", 10)
		pdf.Write(5, tr("Verdict global : "))
		pdf.SetFont("Arial", "B", 10)
		if c.Conform {
			pdf.SetTextColor(10, 125, 50) // vert
		} else {
			pdf.SetTextColor(179, 38, 30) // rouge
		}
		pdf.Write(5, tr(verdictText(c.Conform)))
		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Arial", "", 10)
		pdf.Write(5, tr(fmt.Sprintf(" au niveau %s.", c.Level)))
		pdf.Ln(6)
		para(fmt.Sprintf("Maturité totale : %s/5 (seuil requis : %s).",
			score2(c.TotalMaturity), score2(c.TotalThreshold)))
		if len(c.NonConformKeyMeasures) > 0 {
			para("Mesures clés (Key Measures) non conformes, à traiter en priorité :")
			for _, km := range c.NonConformKeyMeasures {
				bullet(km)
			}
		} else {
			para("Toutes les mesures clés atteignent le seuil requis.")
		}
	}
	if len(c.Categories) > 0 {
		para("Maturité par catégorie (documentation / implementation / maturité, calcul de l'outil du CCB) :")
		for _, cs := range c.Categories {
			bullet(fmt.Sprintf("%s  %s / %s / %s", cs.Category, score2(cs.Documentation), score2(cs.Implementation), score2(cs.Maturity)))
		}
	}

	// --- 2. Contexte et méthodologie ---
	heading("2. Contexte et méthodologie")
	para(fmt.Sprintf("Périmètre (fourni par %s, aucune découverte réseau) — %d hôte(s) :",
		s.Scope.ProvidedBy, len(s.Scope.Hosts)))
	for _, h := range s.Scope.Hosts {
		desc := h.Ref.OS
		if h.Ref.Role != "" {
			desc += ", " + h.Ref.Role
		}
		bullet(fmt.Sprintf("%s (%s)", h.Ref.ID, desc))
	}
	para("Méthode : collecte technique en lecture seule (contrôles scannables) + " +
		"questionnaire déclaratif (contrôles organisationnels). Chaque requirement reçoit " +
		"une note Documentation et une note Implementation (échelle 1–5) ; la maturité est " +
		"leur moyenne.")
	para("Limites : l'audit reflète l'état constaté sur le périmètre fourni à la date " +
		"d'export ; il ne préjuge pas d'une certification officielle.")

	// --- 3. Résultats détaillés par fonction NIST ---
	heading("3. Résultats détaillés par fonction NIST")
	// En-têtes et largeurs du tableau des contrôles : le requirement occupe la
	// plus grande colonne car il peut être long (MultiCell = repli sur lignes).
	resultHeaders := []string{"ID / Requirement", "Doc", "Impl", "Maturité"}
	resultWidths := []float64{120, 20, 20, 20} // total = 180
	for _, g := range v.Groups {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 11)
		pdf.SetTextColor(0, 0, 0)
		pdf.MultiCell(contentW, 6, tr(string(g.Function)), "", "L", false)
		drawTableHeader(pdf, tr, resultHeaders, resultWidths)
		for _, cv := range g.Controls {
			idReq := cv.Meta.ID
			if cv.Meta.KeyMeasure {
				idReq += " (Key Measure)"
			}
			idReq += "\n" + cv.Meta.Requirement
			cells := []string{idReq, lvlText(cv.Doc), lvlText(cv.Impl), score2(cv.Maturity)}
			drawTableRow(pdf, tr, cells, resultWidths, cv.Meta.KeyMeasure)
		}
	}

	// --- 4. Plan de remédiation priorisé ---
	heading("4. Plan de remédiation priorisé")
	if len(v.Remediation) == 0 {
		para("Aucune remédiation requise : tous les contrôles atteignent les seuils.")
	} else {
		remHeaders := []string{"Priorité", "ID / Requirement", "Maturité", "Écart"}
		remWidths := []float64{20, 115, 22, 23} // total = 180
		drawTableHeader(pdf, tr, remHeaders, remWidths)
		for _, it := range v.Remediation {
			idReq := it.Meta.ID
			if it.Meta.KeyMeasure {
				idReq += " (Key Measure)"
			}
			idReq += "\n" + it.Meta.Requirement
			gap := "—"
			if it.Gap > 0 {
				gap = "+" + score2(it.Gap)
			}
			cells := []string{
				fmt.Sprintf("%d", it.Priority), idReq,
				score2(it.Maturity) + "/5", gap,
			}
			drawTableRow(pdf, tr, cells, remWidths, it.Meta.KeyMeasure)
		}
	}

	// --- 5. Annexe technique ---
	heading("5. Annexe technique")
	// Mention IMPÉRATIVE de la règle de sécurité absolue du projet : les scripts
	// de remédiation sont TOUJOURS générés pour validation humaine et JAMAIS
	// exécutés automatiquement. Ce texte ne doit pas disparaître du rapport.
	banner("Sécurité : les scripts de remédiation proposés (PowerShell / Bash) sont " +
		"TOUJOURS générés à des fins de VALIDATION HUMAINE avant toute exécution, et ne " +
		"sont JAMAIS exécutés automatiquement. Cet outil ne modifie jamais automatiquement " +
		"la configuration des systèmes audités.")

	// --- 6. Annexe légale ---
	heading("6. Annexe légale")
	banner(s.Disclaimer)
	para(v.NIS2Note)
	para("Traitement des données : seules les données strictement nécessaires à l'audit " +
		"sont collectées (RGPD, principe de minimisation). Les identifiants d'accès fournis " +
		"par le client ne sont jamais conservés ni inscrits dans ce rapport. Le présent " +
		"document constitue une auto-évaluation assistée et n'engage pas la responsabilité " +
		"d'un organisme de certification.")

	// Sérialisation en mémoire (stateless : rien n'est écrit sur disque). fpdf
	// accumule ses erreurs éventuelles ; Output les fait remonter.
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drawTableHeader dessine la ligne d'en-tête d'un tableau : fond gris, gras.
func drawTableHeader(pdf *fpdf.Fpdf, tr func(string) string, headers []string, widths []float64) {
	pdf.SetFont("Arial", "B", 9)
	pdf.SetTextColor(0, 0, 0)
	pdf.SetFillColor(244, 244, 244)
	for i, h := range headers {
		pdf.CellFormat(widths[i], 7, tr(h), "1", 0, "L", true, 0, "")
	}
	pdf.Ln(-1) // -1 => hauteur de la dernière cellule imprimée
}

// drawTableRow dessine une ligne dont la PREMIÈRE colonne peut se replier sur
// plusieurs lignes (le requirement). fpdf ne sait pas nativement dessiner une
// ligne de tableau à cellules multi-lignes de hauteurs égales : on le fait donc
// « à la main ».
//
// Technique : on mesure d'abord le nombre de lignes qu'occupera la première
// colonne (SplitLines), on en déduit la hauteur de ligne, puis on dessine la
// colonne repliée (MultiCell) et on repositionne le curseur pour aligner les
// autres colonnes (CellFormat) sur la MÊME hauteur.
func drawTableRow(pdf *fpdf.Fpdf, tr func(string) string, cells []string, widths []float64, key bool) {
	const lineH = 4.5 // hauteur d'une ligne de texte en mm
	pdf.SetFont("Arial", "", 8)
	pdf.SetTextColor(0, 0, 0)

	// Nombre de lignes nécessaires pour la première colonne, à sa largeur.
	nbLines := len(pdf.SplitLines([]byte(tr(cells[0])), widths[0]-2)) // -2 : marge interne cellule
	if nbLines < 1 {
		nbLines = 1
	}
	rowH := float64(nbLines) * lineH

	// Saut de page manuel : si la ligne complète ne tient pas sous la marge
	// basse, on force une nouvelle page AVANT de dessiner (sinon MultiCell
	// casserait la ligne au milieu et désalignerait les colonnes fixes).
	_, _, _, bottom := pdf.GetMargins()
	_, pageH := pdf.GetPageSize()
	if pdf.GetY()+rowH > pageH-bottom {
		pdf.AddPage()
	}

	// Les Key Measures sont surlignées (fond crème) comme dans le HTML.
	fill := key
	if fill {
		pdf.SetFillColor(255, 246, 224)
	}

	x0, y0 := pdf.GetX(), pdf.GetY()

	// Colonne 1 : le requirement, replié sur nbLines lignes, bordure complète.
	pdf.MultiCell(widths[0], lineH, tr(cells[0]), "1", "L", fill)

	// Colonnes suivantes : cellules simples de hauteur rowH, alignées à droite
	// de la première. On repositionne le curseur à l'origine de la ligne.
	x := x0 + widths[0]
	for i := 1; i < len(cells); i++ {
		pdf.SetXY(x, y0)
		pdf.CellFormat(widths[i], rowH, tr(cells[i]), "1", 0, "CM", fill, 0, "")
		x += widths[i]
	}
	// Curseur au début de la ligne suivante (sous la colonne la plus haute).
	pdf.SetXY(x0, y0+rowH)
}

// verdictText : libellé du verdict de conformité (identique au HTML).
func verdictText(ok bool) string {
	if ok {
		return "CONFORME"
	}
	return "NON CONFORME"
}

// score2 formate une maturité avec 2 décimales (les maturités sont des .0/.5).
func score2(s cyfun.MaturityScore) string {
	return fmt.Sprintf("%.2f", float64(s))
}

// lvlText affiche un niveau de maturité entier, ou "n/a" s'il n'a pas été évalué.
func lvlText(l cyfun.MaturityLevel) string {
	if l == cyfun.NotAssessed {
		return "n/a"
	}
	return fmt.Sprintf("%d", int(l))
}
