package engine

import (
	"regexp"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/scan"
)

// Toutes les sondes Windows, tous niveaux confondus, doivent tenir dans la ligne
// de commande cmd.exe que construit la bibliothèque WinRM (8191 caractères) :
// une sonde plus longue échoue sur l'hôte (« La ligne de commande est trop
// longue », constaté le 28/09/2026).
func TestSondesWindows_TiennentDansLaLigneDeCommande(t *testing.T) {
	n := 0
	for _, c := range ControlsForLevel(cyfun.LevelEssential) {
		cmd, ok := c.Commands["windows"]
		if !ok {
			continue
		}
		n++
		if l := scan.WinRMCommandLineLength(cmd.Script); l > scan.MaxWinRMCommandLine {
			t.Errorf("%s : ligne de commande WinRM de %d caractères (> %d)", c.Meta.ID, l, scan.MaxWinRMCommandLine)
		}
	}
	if n != 64 {
		t.Errorf("%d contrôles avec sonde Windows, attendu 64", n)
	}
}

// Défense en profondeur côté Windows : aucun verbe PowerShell d'écriture, de
// changement d'état ou d'exécution distante ne doit apparaître dans une sonde.
func TestSondesWindows_AucunVerbeDEcriture(t *testing.T) {
	interdit := regexp.MustCompile(`(?i)\b(Set|Remove|Add|Clear|Stop|Start|Restart|Suspend|Resume|Disable|Enable|Install|Uninstall|Register|Unregister|Rename|Move|Copy|Import|Invoke|Update|Reset|Write-EventLog|New-Item|New-ItemProperty|New-LocalUser|New-Service)-?\w*\b|\breg\s+(add|delete|import)\b|schtasks\s+/(create|delete|change|run|end)|\bsc(\.exe)?\s+(config|stop|start|delete)\b|netsh\s+\S+\s+(set|add|delete)\b`)
	for _, c := range ControlsForLevel(cyfun.LevelEssential) {
		cmd, ok := c.Commands["windows"]
		if !ok {
			continue
		}
		// Les noms de propriétés et libellés lus (ex. « UserMayNotChangePassword »,
		// « LastInstallationSuccessDate ») ne sont pas des verbes : on ne vérifie que
		// les formes Verbe-Nom et les commandes natives.
		for _, m := range interdit.FindAllString(cmd.Script, -1) {
			if strings.Contains(m, "-") || strings.HasPrefix(strings.ToLower(m), "reg") || strings.HasPrefix(strings.ToLower(m), "sc") || strings.HasPrefix(strings.ToLower(m), "netsh") || strings.HasPrefix(strings.ToLower(m), "schtasks") {
				t.Errorf("%s : commande d'écriture %q dans une sonde Windows", c.Meta.ID, m)
			}
		}
	}
}
