package report

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// HTML produit le rapport d'audit complet en HTML autonome (styles inline, pas
// de ressource externe : lisible hors-ligne, empaquetable via embed.FS). On
// utilise html/template : tout contenu issu des données client est échappé
// automatiquement — pas d'injection possible via un nom d'hôte ou un constat.
func HTML(v View) ([]byte, error) {
	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// verdictClass / levelLabel : petites aides d'affichage.
var htmlFuncs = template.FuncMap{
	"pct1": func(s cyfun.MaturityScore) string { return fmt.Sprintf("%.2f", float64(s)) },
	"lvl": func(l cyfun.MaturityLevel) string {
		if l == cyfun.NotAssessed {
			return "n/a"
		}
		return fmt.Sprintf("%d", int(l))
	},
	"verdict": func(ok bool) string {
		if ok {
			return "CONFORME"
		}
		return "NON CONFORME"
	},
	"badge": func(ok bool) template.HTMLAttr {
		if ok {
			return template.HTMLAttr(`style="color:#0a7d32;font-weight:bold"`)
		}
		return template.HTMLAttr(`style="color:#b3261e;font-weight:bold"`)
	},
}

var htmlTmpl = template.Must(template.New("report").Funcs(htmlFuncs).Parse(`<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Rapport d'audit CyFun Basic — {{.Session.Scope.ClientRef}}</title>
<style>
body{font-family:system-ui,Arial,sans-serif;max-width:960px;margin:2rem auto;color:#1a1a1a;line-height:1.5;padding:0 1rem}
h1,h2{border-bottom:2px solid #ccc;padding-bottom:.3rem}
table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.92rem}
th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}
th{background:#f4f4f4}
.km{background:#fff6e0}
.disclaimer{background:#fff8e1;border:1px solid #e0c060;padding:.8rem;border-radius:4px}
small{color:#666}
</style></head><body>

<h1>Rapport d'auto-évaluation CyFun — Niveau {{.Session.Framework.Level}}</h1>
<p><strong>Client :</strong> {{.Session.Scope.ClientRef}}<br>
<strong>Référentiel :</strong> {{.Session.Framework.Name}} {{.Session.Framework.Version}} (aligné NIST CSF 2.0)<br>
<strong>Session :</strong> {{.Session.SessionID}} — exportée le {{.Session.ExportedAt.Format "2006-01-02 15:04"}}</p>
<p class="disclaimer">{{.Session.Disclaimer}}</p>

<h2>1. Synthèse exécutive</h2>
{{if .Session.Conformity.Incomplete}}
<p class="disclaimer">Verdict global : <span style="color:#8a6d00;font-weight:bold">AUDIT INCOMPLET —
{{len .Session.Conformity.UnassessedControls}} contrôle(s) à évaluer</span>
au niveau {{.Session.Conformity.Level}}. Aucun verdict de conformité n'est délivré tant que
des contrôles ne sont pas évalués : chacun doit être couvert par le scan, attesté via le
questionnaire de repli, marqué non applicable, ou tranché par un override consultant.</p>
<p>Maturité <em>partielle</em> (sur les seuls contrôles évalués) :
<strong>{{pct1 .Session.Conformity.TotalMaturity}}/5</strong>
(seuil requis : {{pct1 .Session.Conformity.TotalThreshold}}) — indicative, non contractuelle.</p>
<p>Contrôles à compléter :</p>
<ul>{{range .Session.Conformity.UnassessedControls}}<li><code>{{.}}</code></li>{{end}}</ul>
{{else}}
<p>Verdict global : <span {{badge .Session.Conformity.Conform}}>{{verdict .Session.Conformity.Conform}}</span>
au niveau {{.Session.Conformity.Level}}.</p>
<p>Maturité totale : <strong>{{pct1 .Session.Conformity.TotalMaturity}}/5</strong>
(seuil requis : {{pct1 .Session.Conformity.TotalThreshold}}).</p>
{{end}}
{{if .Session.Conformity.NonConformKeyMeasures}}
<p>Mesures clés (Key Measures) non conformes, à traiter en priorité :</p>
<ul>{{range .Session.Conformity.NonConformKeyMeasures}}<li><code>{{.}}</code></li>{{end}}</ul>
{{else}}<p>Toutes les mesures clés atteignent le seuil requis.</p>{{end}}
{{if .Session.Conformity.NonConformCategories}}
<p>Catégories sous le seuil ({{pct1 .Session.Conformity.CategoryThreshold}}/5, niveau {{.Session.Conformity.Level}}) :</p>
<ul>{{range .Session.Conformity.NonConformCategories}}<li><code>{{.}}</code></li>{{end}}</ul>
{{end}}

<h2>2. Contexte et méthodologie</h2>
<p><strong>Périmètre</strong> (fourni par {{.Session.Scope.ProvidedBy}}, aucune découverte réseau) —
{{len .Session.Scope.Hosts}} hôte(s) :</p>
<ul>{{range .Session.Scope.Hosts}}<li>{{.Ref.ID}} <small>({{.Ref.OS}}{{if .Ref.Role}}, {{.Ref.Role}}{{end}})</small></li>{{end}}</ul>
<p><strong>Méthode :</strong> collecte technique en lecture seule (contrôles scannables) + questionnaire
déclaratif (contrôles organisationnels). Chaque requirement reçoit une note Documentation et une note
Implementation (échelle 1–5) ; la maturité est leur moyenne.
<strong>Limites :</strong> l'audit reflète l'état constaté sur le périmètre fourni à la date d'export ;
il ne préjuge pas d'une certification officielle.</p>

<h2>2 bis. Couverture de collecte</h2>
<p>Comment chaque contrôle a réellement été évalué. Un contrôle « scannable » non couvert par le scan
(OS non supporté, droits insuffisants, hôte injoignable) bascule sur l'attestation du questionnaire de
repli ; à défaut, il est marqué <strong>NON ÉVALUÉ</strong> et bloque le verdict. Aucun « scanné » n'est
affiché s'il ne l'a pas été — et aucune élévation de privilèges n'est jamais tentée (par conception).</p>
<table>
<tr><th>Contrôle</th><th>Méthode d'évaluation</th><th>Détail</th></tr>
{{range .Coverage}}<tr><td><code>{{.ID}}</code></td><td>{{.Method}}</td><td><small>{{.Detail}}</small></td></tr>
{{end}}
</table>

<h2>2 ter. Indicateur de risque technique par hôte</h2>
<p><em>Aide au triage, dérivée UNIQUEMENT des constats scannés (ce qui a été réellement
mesuré sur l'hôte). Ce n'est <strong>pas un verdict de conformité</strong> CyFun : les
attestations de repli, contrôles déclaratifs et trous de collecte n'y entrent pas.
Score 0 = aucun risque mesuré ; 100 = risque maximal.</em></p>
{{if .HostRisks}}
<table>
<tr><th>Hôte</th><th>Risque</th><th>Note</th><th>Contrôles mesurés</th><th>Principaux constats</th></tr>
{{range .HostRisks}}<tr><td>{{.HostID}}</td><td>{{.Score}}/100</td><td>{{.Grade}}</td><td>{{.MeasuredControls}}</td><td><small>{{range .TopContributors}}{{.}}<br>{{end}}</small></td></tr>
{{end}}
</table>
{{else}}<p>Aucun constat technique mesuré (audit déclaratif ou hôtes non scannés).</p>{{end}}

<h2>3. Résultats détaillés par fonction NIST</h2>
{{range .Groups}}
<h3>{{.Function}}</h3>
<table>
<tr><th>Requirement</th><th>Doc</th><th>Impl</th><th>Maturité</th><th>Preuve / constat</th></tr>
{{range .Controls}}
<tr{{if .Meta.KeyMeasure}} class="km"{{end}}>
<td><code>{{.Meta.ID}}</code>{{if .Meta.KeyMeasure}} <small>(Key Measure)</small>{{end}}<br>{{.Meta.Requirement}}</td>
<td>{{if .NotApplicable}}N/A{{else}}{{lvl .Doc}}{{end}}</td><td>{{if .NotApplicable}}N/A{{else}}{{lvl .Impl}}{{end}}</td>
<td {{badge .Conform}}>{{if .NotApplicable}}N/A{{else}}{{pct1 .Maturity}}{{end}}</td>
<td>{{if .NotApplicable}}<small>⊘ Non applicable (attesté) : {{.OverrideReason}}</small>{{else}}{{if .Declared}}<small>Contrôle déclaratif (questionnaire)</small>{{else}}{{.Evidence}}{{end}}{{if .Overridden}}<br><small>⚑ Score corrigé (consultant) : proposé {{lvl .ProposedImpl}} → retenu {{lvl .Impl}}. Justification : {{.OverrideReason}}</small>{{end}}{{end}}</td>
</tr>
{{end}}
</table>
{{end}}

<h2>4. Plan de remédiation priorisé</h2>
{{if .Remediation}}
<table>
<tr><th>#</th><th>Contrôle</th><th>Maturité actuelle</th><th>Écart au seuil KM</th></tr>
{{range .Remediation}}
<tr{{if .Meta.KeyMeasure}} class="km"{{end}}>
<td>{{.Priority}}</td>
<td><code>{{.Meta.ID}}</code>{{if .Meta.KeyMeasure}} <small>(Key Measure)</small>{{end}} — {{.Meta.Requirement}}</td>
<td>{{pct1 .Maturity}}/5</td>
<td>{{if gt (pct1 .Gap) "0.00"}}+{{pct1 .Gap}}{{else}}—{{end}}</td>
</tr>
{{end}}
</table>
{{else}}<p>Aucune remédiation requise : tous les contrôles atteignent les seuils.</p>{{end}}

<h2>4 bis. Objectif excellence (5/5)</h2>
<p>Le niveau maximal (5 — « Optimizing ») exige : {{.Level5}} Il ne s'attribue que
sur <strong>preuve</strong> (métriques, amélioration continue) — jamais par le seul
scan. Contrôles à faire progresser vers 5/5 (feuille de route d'amélioration) :</p>
{{if .Excellence}}
<table>
<tr><th>Contrôle</th><th>Maturité actuelle</th><th>Écart au 5/5</th></tr>
{{range .Excellence}}
<tr{{if .Meta.KeyMeasure}} class="km"{{end}}>
<td><code>{{.Meta.ID}}</code>{{if .Meta.KeyMeasure}} <small>(Key Measure)</small>{{end}} — {{.Meta.Requirement}}</td>
<td>{{pct1 .Maturity}}/5</td>
<td>+{{pct1 .ExcellenceGap}}</td>
</tr>
{{end}}
</table>
{{else}}<p>Tous les contrôles sont déjà au niveau maximal (5/5).</p>{{end}}

<h2>5. Annexe technique</h2>
<p class="disclaimer"><strong>Sécurité :</strong> les scripts de remédiation proposés (PowerShell / Bash)
sont fournis à titre indicatif et destinés à une <strong>validation humaine</strong> avant toute
exécution. Cet outil ne modifie <strong>jamais</strong> automatiquement la configuration des systèmes
audités.</p>

<h2>6. Annexe légale</h2>
<p class="disclaimer">{{.Session.Disclaimer}}</p>
<p><small>Traitement des données : seules les données strictement nécessaires à l'audit sont collectées
(RGPD, minimisation). Les identifiants d'accès fournis par le client ne sont jamais conservés ni
inscrits dans ce rapport. Le présent document constitue une auto-évaluation assistée et n'engage pas
la responsabilité d'un organisme de certification.</small></p>

</body></html>`))
