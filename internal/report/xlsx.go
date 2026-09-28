package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// XLSX produit un classeur .xlsx (Office Open XML) résumant l'audit, sans
// aucune dépendance : un .xlsx N'EST qu'une archive zip de fichiers XML. On
// écrit les cellules texte en "inlineStr" (chaîne embarquée dans la cellule),
// ce qui évite de gérer une table de chaînes partagées — plus simple et tout
// aussi valide. Les scores partent en cellules numériques (exploitables par un
// tableur : filtres, moyennes).
func XLSX(v View) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	files := map[string]string{
		"[Content_Types].xml":        contentTypesXML,
		"_rels/.rels":                rootRelsXML,
		"xl/workbook.xml":            workbookXML,
		"xl/_rels/workbook.xml.rels": workbookRelsXML,
		"xl/worksheets/sheet1.xml":   sheetXML(v),
	}
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- squelette OOXML minimal (fixe) ---

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`

const rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`

const workbookXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Synthèse" sheetId="1" r:id="rId1"/></sheets>
</workbook>`

const workbookRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`

// --- feuille de synthèse (dynamique) ---

// cell est soit du texte (inlineStr), soit un nombre.
type cell struct {
	text  string
	num   float64
	isNum bool
}

func txt(s string) cell               { return cell{text: s} }
func numf(f float64) cell             { return cell{num: f, isNum: true} }
func numl(l cyfun.MaturityLevel) cell { return cell{num: float64(l), isNum: true} }

// sheetXML assemble la feuille : bandeau (titre, verdict, disclaimer) puis un
// tableau une ligne par contrôle.
func sheetXML(v View) string {
	var rows []string
	rowNum := 0
	addRow := func(cells ...cell) {
		rowNum++
		rows = append(rows, rowXML(rowNum, cells))
	}

	c := v.Session.Conformity
	verdict := "NON CONFORME"
	switch {
	case c.Incomplete:
		verdict = fmt.Sprintf("AUDIT INCOMPLET (%d contrôle(s) à évaluer)", len(c.UnassessedControls))
	case c.Conform:
		verdict = "CONFORME"
	}
	addRow(txt("Rapport CyFun " + v.Session.Framework.Level + " — " + v.Session.Scope.ClientRef))
	addRow(txt("Verdict"), txt(verdict), txt(fmt.Sprintf("Maturité totale %.2f/5 (seuil %.1f)",
		float64(c.TotalMaturity), float64(c.TotalThreshold))))
	addRow(txt(v.Session.Disclaimer))
	addRow() // ligne vide
	addRow(txt("ID"), txt("Fonction"), txt("Catégorie"), txt("Key Measure"),
		txt("Documentation"), txt("Implementation"), txt("Maturité"), txt("Conforme"))

	for _, g := range v.Groups {
		for _, cv := range g.Controls {
			km, conf := "non", "oui"
			if cv.Meta.KeyMeasure {
				km = "OUI"
			}
			if !cv.Conform {
				conf = "NON"
			}
			addRow(txt(cv.Meta.ID), txt(string(cv.Meta.Function)), txt(cv.Meta.Category), txt(km),
				numl(cv.Doc), numl(cv.Impl), numf(float64(cv.Maturity)), txt(conf))
		}
	}

	if len(c.Categories) > 0 {
		addRow()
		addRow(txt("Maturité par catégorie (calcul de l'onglet Summary de l'outil CCB)"))
		addRow(txt("Fonction"), txt("Catégorie"), txt("Documentation"), txt("Implementation"), txt("Maturité"))
		for _, cs := range c.Categories {
			addRow(txt(cs.Function), txt(cs.Category), numf(float64(cs.Documentation)),
				numf(float64(cs.Implementation)), numf(float64(cs.Maturity)))
		}
	}

	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>` + join(rows) + `</sheetData></worksheet>`
}

// rowXML sérialise une ligne ; colonnes A, B, C... dans l'ordre des cellules.
func rowXML(rowNum int, cells []cell) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, `<row r="%d">`, rowNum)
	for i, cl := range cells {
		ref := fmt.Sprintf("%s%d", colName(i), rowNum)
		if cl.isNum {
			fmt.Fprintf(&b, `<c r="%s"><v>%s</v></c>`, ref, trimNum(cl.num))
		} else {
			fmt.Fprintf(&b, `<c r="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`, ref, escape(cl.text))
		}
	}
	b.WriteString(`</row>`)
	return b.String()
}

// colName convertit 0->A, 1->B, ... 25->Z, 26->AA (suffisant au-delà de nos 8 colonnes).
func colName(i int) string {
	name := ""
	for {
		name = string(rune('A'+i%26)) + name
		i = i/26 - 1
		if i < 0 {
			break
		}
	}
	return name
}

func trimNum(f float64) string {
	// entier -> sans décimale ; sinon 2 décimales (les maturités sont des .0/.5).
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%.2f", f)
}

func escape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func join(ss []string) string {
	var b bytes.Buffer
	for _, s := range ss {
		b.WriteString(s)
	}
	return b.String()
}
