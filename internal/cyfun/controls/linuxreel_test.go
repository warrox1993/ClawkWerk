package controls

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// Tests issus de la validation réelle sur Ubuntu 26.04 (hôte JBsTower, compte
// non root, 28/09/2026). Chaque cas reprend une sortie constatée.

func TestFirewallLinux_UfwLisibleParSaConfiguration(t *testing.T) {
	raw := "# outils\noutil: ufw\noutil: nft\noutil: iptables\n# etat\nillisible: ufw\nconfig: ufw actif\nDEFAULT_INPUT_POLICY=\"DROP\"\nillisible: nft\nillisible: iptables\n"
	out, err := FirewallLinuxNormalizer([]byte(raw))
	if err != nil {
		t.Fatalf("ufw activé par configuration : preuve attendue, obtenu %v", err)
	}
	var ev FirewallEvidence
	_ = json.Unmarshal(out, &ev)
	if !ev.Enabled || !ev.DefaultInboundDeny {
		t.Fatalf("ufw actif / entrée bloquée attendu : %+v", ev)
	}
	// Sans la ligne de configuration, un ufw illisible reste un trou de droits.
	if _, err := FirewallLinuxNormalizer([]byte("# outils\noutil: ufw\n# etat\nillisible: ufw\n")); err == nil || !strings.Contains(err.Error(), "droits insuffisants") {
		t.Fatalf("ufw illisible sans configuration : « droits insuffisants » attendu, obtenu %v", err)
	}
}

func TestLoggingLinux_RetentionMesuree(t *testing.T) {
	out, err := LoggingLinuxNormalizer([]byte("active\n22\nno\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	_ = json.Unmarshal(out, &ev)
	if ev.RetentionDays != 22 {
		t.Fatalf("rétention mesurée : %d", ev.RetentionDays)
	}
	if _, err := LoggingLinuxNormalizer([]byte("active\njournal illisible: No journal files were opened due to insufficient permissions.\nno\n")); err == nil {
		t.Fatal("une rétention non mesurable ne doit jamais devenir une valeur")
	}
}

func TestLocalAdminLinux_RootIllisible(t *testing.T) {
	out, err := LocalAdminLinuxNormalizer([]byte("1\nunknown\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ev LocalAdminEvidence
	_ = json.Unmarshal(out, &ev)
	if !ev.BuiltinAdminUnknown {
		t.Fatal("root illisible doit être marqué inconnu, pas « actif »")
	}
	ha := evaluateLocalAdmin(assess.HostRef{ID: "L"}, ev)
	if !strings.Contains(ha.Findings[0].Message, "non lisible") {
		t.Fatalf("message : %q", ha.Findings[0].Message)
	}
	out, _ = LocalAdminLinuxNormalizer([]byte("1\nyes\n"))
	ev = LocalAdminEvidence{}
	_ = json.Unmarshal(out, &ev)
	if ev.BuiltinAdminUnknown || !ev.BuiltinAdminDisabled {
		t.Fatalf("root verrouillé : %+v", ev)
	}
}

func TestAccessReviewLinux_DerniereConnexionInconnue(t *testing.T) {
	out, err := AccessReviewLinuxNormalizer([]byte("1\nunknown\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ev AccessReviewEvidence
	_ = json.Unmarshal(out, &ev)
	if !ev.InactiveUnknown {
		t.Fatal("sans lastlog, la dormance est inconnue (et non « 0 dormant »)")
	}
	ha := evaluateAccessReview(assess.HostRef{ID: "L"}, ev)
	if ha.ProposedImplLevel != cyfun.Repeatable {
		t.Fatalf("attendu Repeatable, obtenu %v", ha.ProposedImplLevel)
	}
	d := Dormant0103Evaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "L"}, Data: out})
	if d.ProposedImplLevel != cyfun.Repeatable {
		t.Fatalf("PR.AA-01.3 : attendu Repeatable, obtenu %v", d.ProposedImplLevel)
	}
}

func TestAutorunEtTransitLinux_InconnusNonConclus(t *testing.T) {
	boot, _ := BootDeviceLinuxNormalizer([]byte("yes\nno\nunknown\n"))
	ha := AutorunEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "L"}, Data: boot})
	if ha.ProposedImplLevel != cyfun.NotAssessed || ha.Findings[0].Status != assess.StatusError {
		t.Fatalf("autorun sans réglage système : non évalué attendu, obtenu %v/%s", ha.ProposedImplLevel, ha.Findings[0].Status)
	}
	enc, _ := EncryptionLinuxNormalizer([]byte("no\nunknown\nno\n"))
	ha = InTransitEncryptionEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "L"}, Data: enc})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Fatalf("sans Samba : non évalué attendu, obtenu %v", ha.ProposedImplLevel)
	}
	// Une vraie réponse reste interprétée.
	enc, _ = EncryptionLinuxNormalizer([]byte("yes\nyes\nno\n"))
	ha = InTransitEncryptionEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "L"}, Data: enc})
	if ha.ProposedImplLevel == cyfun.NotAssessed {
		t.Fatal("Samba signé : constat attendu")
	}
}

func TestSondesLinux_PlusDeValeursEnDur(t *testing.T) {
	// L'autorun n'est plus « yes » en dur ; AppArmor n'est plus pris pour de
	// l'allowlisting ; la politique PAM effective est lue.
	if strings.HasSuffix(BootDeviceLinuxCmd, "echo yes`") || strings.HasSuffix(BootDeviceLinuxCmd, "echo yes") {
		t.Error("BootDeviceLinuxCmd : autorun émis en dur")
	}
	if strings.Contains(AppControlLinuxCmd, "aa-status") {
		t.Error("AppControlLinuxCmd : AppArmor (MAC) n'est pas un allowlisting applicatif")
	}
	if !strings.Contains(PRAA0101LinuxCmd, "pam_pwquality") {
		t.Error("PRAA0101LinuxCmd : la politique PAM effective doit être lue")
	}
}
