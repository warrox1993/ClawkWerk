package report

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/scope"
	"github.com/warrox1993/clawkwerk/internal/session"
)

// sessionForTest fabrique une session à deux contrôles : un Key Measure non
// conforme (scannable) et un contrôle déclaratif conforme.
func sessionForTest() session.AuditSession {
	results := []assess.ControlResult{
		{
			Meta: cyfun.ControlMeta{ID: "DE.CM-01.2", Function: cyfun.Detect, Category: "DE.CM",
				Requirement: "Anti-virus shall be installed and updated.", Level: "Basic", KeyMeasure: true},
			HostAssessments: []assess.HostAssessment{{
				Host:     assess.HostRef{ID: "SRV01"},
				Findings: []assess.Finding{{HostID: "SRV01", Status: assess.StatusFail, Message: "Aucun antivirus détecté."}},
			}},
			FinalDoc: cyfun.Defined, FinalImpl: cyfun.Initial, // moyenne 2,0 < 2,5 => KM non conforme
		},
		{
			Meta: cyfun.ControlMeta{ID: "GV.PO-01.1", Function: cyfun.Govern, Category: "GV.PO",
				Requirement: "Policies shall be established.", Level: "Basic", KeyMeasure: false},
			FinalDoc: cyfun.Defined, FinalImpl: cyfun.Managed, // 3,5 => conforme, hors plan
		},
	}
	sc := scope.AuditScope{ClientRef: "ACME", ProvidedBy: "DSI",
		Hosts: []scope.ScopedHost{{Ref: assess.HostRef{ID: "SRV01", OS: "windows", Role: "server"}}}}
	return session.New("test-1", sc, results, nil, time.Unix(0, 0), time.Unix(0, 0))
}

func TestBuild_GroupsAndRemediation(t *testing.T) {
	v := Build(sessionForTest())

	// GOVERN doit précéder DETECT dans l'ordre du référentiel.
	if len(v.Groups) != 2 || v.Groups[0].Function != cyfun.Govern || v.Groups[1].Function != cyfun.Detect {
		t.Fatalf("regroupement/ordre NIST inattendu: %+v", v.Groups)
	}
	// Seul le KM non conforme doit figurer au plan de remédiation.
	if len(v.Remediation) != 1 {
		t.Fatalf("attendu 1 item de remédiation, obtenu %d", len(v.Remediation))
	}
	item := v.Remediation[0]
	if item.Meta.ID != "DE.CM-01.2" || item.Priority != 1 {
		t.Errorf("remédiation: got %s prio %d", item.Meta.ID, item.Priority)
	}
	if item.Gap != 0.5 { // 2,5 - 2,0
		t.Errorf("écart au seuil KM attendu 0.5, obtenu %v", item.Gap)
	}
}

func TestHTML_ContainsKeyElements(t *testing.T) {
	v := Build(sessionForTest())
	out, err := HTML(v)
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	for _, want := range []string{
		"NON CONFORME",
		"Anti-virus shall be installed and updated.", // texte exact du requirement
		session.Disclaimer,                           // mention légale obligatoire
		"Plan de remédiation",
		"Aucun antivirus détecté.", // preuve remontée
		"validation humaine",       // règle de sécurité remédiation
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML ne contient pas %q", want)
		}
	}
}

func TestXLSX_IsValidZipWithSheet(t *testing.T) {
	v := Build(sessionForTest())
	out, err := XLSX(v)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("xlsx n'est pas un zip valide: %v", err)
	}
	// parts obligatoires présentes ?
	need := map[string]bool{"[Content_Types].xml": false, "xl/workbook.xml": false, "xl/worksheets/sheet1.xml": false}
	var sheet string
	for _, f := range zr.File {
		if _, ok := need[f.Name]; ok {
			need[f.Name] = true
		}
		if f.Name == "xl/worksheets/sheet1.xml" {
			rc, _ := f.Open()
			var b bytes.Buffer
			b.ReadFrom(rc)
			rc.Close()
			sheet = b.String()
		}
	}
	for name, ok := range need {
		if !ok {
			t.Errorf("part manquante dans le xlsx: %s", name)
		}
	}
	// la feuille doit contenir l'ID de contrôle et le verdict.
	if !strings.Contains(sheet, "DE.CM-01.2") || !strings.Contains(sheet, "NON CONFORME") {
		t.Errorf("feuille de synthèse incomplète: %s", sheet)
	}
}

// Le classeur XLSX ne doit jamais afficher « NON CONFORME » pour un audit
// incomplet (verdict bloqué), et reprend la maturité par catégorie.
func TestXLSX_AuditIncompletEtCategories(t *testing.T) {
	sess := session.AuditSession{Framework: session.Framework{Level: "Basic"}}
	sess.Conformity = session.ConformitySummary{Incomplete: true, UnassessedControls: []string{"GV.OC-03.1"},
		Categories: []session.CategoryScore{{Category: "GV.OC", Function: "GOVERN", Documentation: 3, Implementation: 2, Maturity: 2.5}}}
	xml := sheetXML(Build(sess))
	if strings.Contains(xml, "NON CONFORME") || !strings.Contains(xml, "AUDIT INCOMPLET") {
		t.Fatal("audit incomplet : le verdict XLSX doit être « AUDIT INCOMPLET »")
	}
	if !strings.Contains(xml, "GV.OC") {
		t.Fatal("maturité par catégorie absente du XLSX")
	}
}

// Positionnement légal : chaque rapport rappelle qu'il ne s'agit ni d'une
// vérification ni d'une certification CyFun, ni d'une présomption de
// conformité NIS2, et cite la source officielle du CCB.
func TestRapports_PositionnementNIS2(t *testing.T) {
	v := Build(sessionForTest())
	h, err := HTML(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"ni une présomption de conformité NIS2", "autorisé par le CCB", "atwork.safeonweb.be/nis2"} {
		if !strings.Contains(string(h), s) {
			t.Errorf("HTML : mention %q absente", s)
		}
	}
	for _, interdit := range []string{"certifié", "certifie votre", "conforme NIS2"} {
		if strings.Contains(strings.ToLower(string(h)), interdit) {
			t.Errorf("HTML : formulation trompeuse %q", interdit)
		}
	}
}
