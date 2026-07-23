package report

import (
	"bytes"
	"testing"
)

// TestPDF_ProducesValidPDFHeader vérifie le contrat minimal du générateur PDF :
// il renvoie des octets, sans erreur, et le flux commence par l'entête magique
// « %PDF » (les 4 premiers octets de tout fichier PDF). On ne parse pas le PDF
// en profondeur — fpdf est éprouvé ; on s'assure surtout que Build -> PDF ne
// panique pas et produit bien un document non vide et reconnaissable.
func TestPDF_ProducesValidPDFHeader(t *testing.T) {
	v := Build(sessionForTest()) // même session de test que le reste du paquet

	out, err := PDF(v)
	if err != nil {
		t.Fatalf("PDF() a renvoyé une erreur: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("PDF() a renvoyé un document vide")
	}
	if !bytes.HasPrefix(out, []byte("%PDF")) {
		// on n'affiche que le début pour ne pas noyer la sortie de test.
		head := out
		if len(head) > 8 {
			head = head[:8]
		}
		t.Errorf("entête PDF manquante ; premiers octets = %q", head)
	}
}
