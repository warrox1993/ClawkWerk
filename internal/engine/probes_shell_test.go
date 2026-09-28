package engine

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/cyfun/controls"
)

// Ces tests EXÉCUTENT les sondes Linux dans un vrai shell POSIX, avec un PATH
// réduit à un répertoire contrôlé : quelques utilitaires de texte réels (grep,
// awk…) et des faux outils système (ss, ufw, systemctl…) dont on choisit la
// sortie et le code retour. Ils prouvent qu'une sonde se termine par un code
// nul sur une machine saine ou dépourvue de l'outil sondé, puisque le
// transport SSH traite tout code non nul comme une collecte échouée.

// sbinSuffix est le complément de PATH ajouté par les sondes (voir
// controls.FirewallLinuxCmd). Les tests le redirigent vers le répertoire
// contrôlé pour ne jamais lire les vrais /usr/sbin et /sbin de la machine.
const sbinSuffix = "/usr/sbin:/sbin"

// textTools = utilitaires réels mis à disposition des sondes.
var textTools = []string{"grep", "awk", "head", "wc", "stat", "cut", "tr", "sed", "cat", "ls", "env", "sort"}

type probeEnv struct {
	t   *testing.T
	dir string
	sh  string
}

func newProbeEnv(t *testing.T) *probeEnv {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("sondes Linux : test exécuté uniquement sous Linux")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("aucun shell POSIX disponible")
	}
	dir := t.TempDir()
	for _, tool := range textTools {
		if p, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(p, filepath.Join(dir, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return &probeEnv{t: t, dir: dir, sh: sh}
}

// stub installe un faux outil : un script qui affiche out et sort avec code.
func (p *probeEnv) stub(name, out string, code int) {
	p.t.Helper()
	script := "#!/bin/sh\ncat <<'__FIN__'\n" + out + "\n__FIN__\nexit " + itoa(code) + "\n"
	if out == "" {
		script = "#!/bin/sh\nexit " + itoa(code) + "\n"
	}
	if err := os.WriteFile(filepath.Join(p.dir, name), []byte(script), 0o755); err != nil {
		p.t.Fatal(err)
	}
}

// stubScript installe un faux outil au corps shell arbitraire.
func (p *probeEnv) stubScript(name, body string) {
	p.t.Helper()
	if err := os.WriteFile(filepath.Join(p.dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		p.t.Fatal(err)
	}
}

// run exécute la sonde et renvoie stdout, stderr et le code de sortie.
func (p *probeEnv) run(cmd string) (string, string, int) {
	p.t.Helper()
	cmd = strings.ReplaceAll(cmd, sbinSuffix, p.dir)
	c := exec.Command(p.sh, "-c", cmd)
	c.Env = []string{"PATH=" + p.dir, "HOME=" + p.dir, "LC_ALL=C"}
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		p.t.Fatalf("exécution impossible : %v", err)
	}
	return stdout.String(), stderr.String(), code
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// mustSucceed exige un code nul, comme le transport SSH.
func (p *probeEnv) mustSucceed(cmd string) string {
	p.t.Helper()
	out, errOut, code := p.run(cmd)
	if code != 0 {
		p.t.Fatalf("la sonde sort avec le code %d (stdout=%q, stderr=%q) : le transport SSH la classerait « collecte échouée »", code, out, errOut)
	}
	return out
}

func TestProbes_UseSbinSuffix(t *testing.T) {
	for name, cmd := range map[string]string{
		"pare-feu": controls.FirewallLinuxCmd, "antivirus": controls.AntivirusLinuxCmd,
		"surface": controls.PRAA0503LinuxCmd, "matériel": controls.HardwareLinuxCmd,
	} {
		if !strings.Contains(cmd, sbinSuffix) {
			t.Errorf("sonde %s : complément de PATH %q absent (les tests ne seraient plus étanches)", name, sbinSuffix)
		}
	}
}

// Régression bogue n°2 : sur une machine saine (aucun protocole legacy),
// `grep -c` sortait en 1 et PR.AA-05.3 tombait en « collecte échouée ».
func TestProbe_PRAA0503_HealthyMachine(t *testing.T) {
	p := newProbeEnv(t)
	p.stub("ss", "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:443 0.0.0.0:*", 0)
	out := p.mustSucceed(controls.PRAA0503LinuxCmd)
	canon, err := controls.HardeningLinuxNormalizer([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	ha := controls.HardeningEvaluator{}.Evaluate(assess.RawEvidence{Data: canon})
	if ha.ProposedImplLevel != cyfun.Managed || ha.Findings[0].Status != assess.StatusPass {
		t.Errorf("machine saine : attendu Managed/pass, obtenu %d/%s (%s)", ha.ProposedImplLevel, ha.Findings[0].Status, out)
	}
}

func TestProbe_PRAA0503_LegacyService(t *testing.T) {
	p := newProbeEnv(t)
	p.stub("ss", "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 5 0.0.0.0:23 0.0.0.0:*", 0)
	out := p.mustSucceed(controls.PRAA0503LinuxCmd)
	canon, err := controls.HardeningLinuxNormalizer([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	var ev controls.HardeningEvidence
	_ = json.Unmarshal(canon, &ev)
	if ev.LegacyServices != 1 || ev.OpenListeningPorts != 2 {
		t.Errorf("telnet non détecté : %+v", ev)
	}
}

func TestProbe_PRAA0503_NoSSFailsExplicitly(t *testing.T) {
	p := newProbeEnv(t)
	out, errOut, code := p.run(controls.PRAA0503LinuxCmd)
	if code == 0 || !strings.Contains(errOut, "ss introuvable") {
		t.Errorf("sans ss, la sonde doit échouer explicitement (code=%d, stdout=%q, stderr=%q)", code, out, errOut)
	}
}

// Régression bogue n°3 : une machine sans aucun pare-feu produisait une sortie
// vide, classée « collecte échouée ». Elle doit être une NON-CONFORMITÉ.
func TestProbe_Firewall_NoFirewallIsNonConformity(t *testing.T) {
	p := newProbeEnv(t)
	out := p.mustSucceed(controls.FirewallLinuxCmd)
	canon, err := controls.FirewallLinuxNormalizer([]byte(out))
	if err != nil {
		t.Fatalf("aucun pare-feu doit être une preuve, pas une erreur : %v (sortie %q)", err, out)
	}
	ha := controls.FirewallEvaluator{}.Evaluate(assess.RawEvidence{Data: canon})
	if ha.Findings[0].Status != assess.StatusFail || ha.ProposedImplLevel != cyfun.Initial {
		t.Errorf("attendu fail/Initial, obtenu %s/%d : %s", ha.Findings[0].Status, ha.ProposedImplLevel, ha.Findings[0].Message)
	}
}

func TestProbe_Firewall_States(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(p *probeEnv)
		wantErr string // non vide : le normaliseur doit refuser avec ce motif
		product string
		enabled bool
		denyIn  bool
	}{
		{"ufw actif", func(p *probeEnv) {
			p.stub("ufw", "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)", 0)
		}, "", "ufw", true, true},
		{"ufw non lisible (compte non root)", func(p *probeEnv) {
			p.stubScript("ufw", "echo 'ERROR: You need to be root to run this script' >&2; exit 1")
		}, "droits insuffisants", "", false, false},
		{"ufw inactif", func(p *probeEnv) { p.stub("ufw", "Status: inactive", 0) }, "", "ufw", false, false},
		{"firewalld en marche", func(p *probeEnv) {
			p.stubScript("firewall-cmd", `case "$1" in --state) echo running;; *) printf 'public (active)\n  target: default\n  services: ssh\n';; esac`)
		}, "", "firewalld", true, true},
		{"firewalld arrêté", func(p *probeEnv) {
			p.stubScript("firewall-cmd", `case "$1" in --state) echo 'not running' >&2; exit 252;; *) exit 252;; esac`)
		}, "", "firewalld", false, false},
		{"nftables politique drop", func(p *probeEnv) {
			p.stub("nft", "table inet filter {\n chain input {\n  type filter hook input priority filter; policy drop;\n }\n}", 0)
		}, "", "nftables", true, true},
		{"nftables lisible mais vide", func(p *probeEnv) { p.stub("nft", "", 0) }, "", "nftables", false, false},
		{"nftables non lisible", func(p *probeEnv) {
			p.stubScript("nft", "echo 'Operation not permitted' >&2; exit 1")
		}, "droits insuffisants", "", false, false},
		{"iptables politique DROP", func(p *probeEnv) {
			p.stub("iptables", "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT", 0)
		}, "", "iptables", true, true},
		{"iptables sans règle", func(p *probeEnv) { p.stub("iptables", "-P INPUT ACCEPT", 0) }, "", "iptables", false, false},
		{"ufw inactif mais nftables actif", func(p *probeEnv) {
			p.stub("ufw", "Status: inactive", 0)
			p.stub("nft", "chain input { type filter hook input priority 0; policy drop; }", 0)
		}, "", "nftables", true, true},
		{"ufw inactif et nft non lisible", func(p *probeEnv) {
			p.stub("ufw", "Status: inactive", 0)
			p.stubScript("nft", "exit 1")
		}, "droits insuffisants", "", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newProbeEnv(t)
			c.setup(p)
			out := p.mustSucceed(controls.FirewallLinuxCmd)
			canon, err := controls.FirewallLinuxNormalizer([]byte(out))
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("attendu une erreur « %s », obtenu %v (sortie %q)", c.wantErr, err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalisation refusée : %v (sortie %q)", err, out)
			}
			var ev controls.FirewallEvidence
			_ = json.Unmarshal(canon, &ev)
			if !ev.Present || ev.Product != c.product || ev.Enabled != c.enabled || ev.DefaultInboundDeny != c.denyIn {
				t.Errorf("preuve inattendue : %+v (sortie %q)", ev, out)
			}
		})
	}
}

func fixedNow() time.Time { return time.Unix(100*86400, 0) }

// Même classe de bogue pour DE.CM-01.2 (Key Measure) : sans ClamAV, le `stat`
// final échouait et la machine était « collecte échouée » au lieu de « aucun
// antivirus ».
func TestProbe_Antivirus(t *testing.T) {
	systemctl := func(active string) string {
		return `for u in "$@"; do :; done; if [ "$u" = "` + active + `" ]; then echo active; exit 0; fi; echo inactive; exit 3`
	}
	cases := []struct {
		name     string
		setup    func(p *probeEnv)
		wantErr  string
		present  bool
		enabled  bool
		wantFail bool
	}{
		{"aucun antivirus", func(p *probeEnv) { p.stubScript("systemctl", systemctl("rien")) }, "", false, false, true},
		{"ClamAV actif", func(p *probeEnv) {
			p.stubScript("systemctl", systemctl("clamav-daemon"))
			p.stub("freshclam", "ClamAV 1.4.3/27777/Mon Sep 28 08:00:00 2026", 0)
		}, "", true, true, false},
		{"ClamAV installé, démon arrêté", func(p *probeEnv) {
			p.stubScript("systemctl", systemctl("rien"))
			p.stub("freshclam", "ClamAV 1.4.3/27777", 0)
		}, "", true, false, true},
		{"anti-malware tiers actif", func(p *probeEnv) { p.stubScript("systemctl", systemctl("mdatp")) }, "anti-malware tiers actif (mdatp)", false, false, false},
		{"systemd absent", func(p *probeEnv) {}, "systemd indisponible", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newProbeEnv(t)
			c.setup(p)
			out := p.mustSucceed(controls.AntivirusLinuxCmd)
			canon, err := controls.AntivirusLinuxNormalizer(fixedNow)([]byte(out))
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("attendu une erreur « %s », obtenu %v (sortie %q)", c.wantErr, err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalisation refusée : %v (sortie %q)", err, out)
			}
			var ev controls.AntivirusEvidence
			_ = json.Unmarshal(canon, &ev)
			if ev.Present != c.present || ev.Enabled != c.enabled {
				t.Errorf("preuve inattendue : %+v (sortie %q)", ev, out)
			}
			ha := controls.AntivirusEvaluator{}.Evaluate(assess.RawEvidence{Data: canon})
			if c.wantFail && ha.Findings[0].Status != assess.StatusFail {
				t.Errorf("attendu une non-conformité, obtenu %s : %s", ha.Findings[0].Status, ha.Findings[0].Message)
			}
		})
	}
}

func TestProbe_Hardware(t *testing.T) {
	p := newProbeEnv(t)
	if _, errOut, code := p.run(controls.HardwareLinuxCmd); code == 0 || !strings.Contains(errOut, "introuvables") {
		t.Errorf("sans lspci ni lsusb, la sonde doit échouer explicitement (code %d, stderr %q)", code, errOut)
	}
	p.stub("lspci", "00:00.0 Host bridge\n00:02.0 VGA compatible controller\n00:1f.3 Audio device", 0)
	if out := p.mustSucceed(controls.HardwareLinuxCmd); strings.TrimSpace(out) != "3" {
		t.Errorf("3 composants attendus, sortie %q", out)
	}
	p.stub("lspci", "", 0) // outil présent, rien d'énuméré : « 0 » avec un code nul
	if out := p.mustSucceed(controls.HardwareLinuxCmd); strings.TrimSpace(out) != "0" {
		t.Errorf("0 composant attendu, sortie %q", out)
	}
}

// Filet de sécurité pour toute la classe de bogue : sur une machine où AUCUN
// outil système sondé n'est installé, chaque sonde Linux du registre (tous
// niveaux) doit sortir avec un code nul, sauf celles qui échouent volontairement
// et explicitement quand leur outil manque.
func TestProbes_AllLinuxProbesExitZeroOnMinimalMachine(t *testing.T) {
	intentional := map[string]bool{
		controls.PRAA0503LinuxCmd: true, // ss requis
		controls.HardwareLinuxCmd: true, // lspci ou lsusb requis
	}
	p := newProbeEnv(t)
	seen := map[string]bool{}
	for _, c := range ControlsForLevel(cyfun.LevelEssential) {
		cmd, ok := c.Commands["linux"]
		if !ok || seen[cmd.Script] {
			continue
		}
		seen[cmd.Script] = true
		out, errOut, code := p.run(cmd.Script)
		if intentional[cmd.Script] {
			if code == 0 {
				t.Errorf("%s : échec explicite attendu quand l'outil manque", c.Meta.ID)
			}
			continue
		}
		if code != 0 {
			t.Errorf("%s : code de sortie %d sur une machine minimale (stdout=%q, stderr=%q)", c.Meta.ID, code, out, errOut)
		}
	}
	if len(seen) < 10 {
		t.Fatalf("trop peu de sondes Linux parcourues (%d)", len(seen))
	}
}

// Le minuteur systemd « dpkg-db-backup » (sauvegarde interne de dpkg, présent
// sur toute Debian/Ubuntu) ne doit pas passer pour une tâche de sauvegarde des
// données.
func TestProbe_Backup_IgnoresDpkgDbBackup(t *testing.T) {
	p := newProbeEnv(t)
	p.stub("systemctl", "NEXT LEFT LAST PASSED UNIT ACTIVATES\n- - - - dpkg-db-backup.timer dpkg-db-backup.service", 0)
	out := p.mustSucceed(controls.PRDS1101LinuxCmd)
	if ls := strings.Fields(out); len(ls) < 2 || ls[1] != "no" {
		t.Errorf("dpkg-db-backup compté comme sauvegarde : %q", out)
	}
	p.stub("systemctl", "- - - - restic-backup.timer restic-backup.service", 0)
	if ls := strings.Fields(p.mustSucceed(controls.PRDS1101LinuxCmd)); ls[1] != "yes" {
		t.Errorf("un vrai minuteur de sauvegarde doit être détecté : %v", ls)
	}
}
