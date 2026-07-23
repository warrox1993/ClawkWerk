package assess

import "projetcyber/internal/cyfun"

// Aggregate combine les évaluations par hôte en un seul niveau proposé au
// contrôle (+ justification). Le défaut du projet est WorstCase (maillon
// faible), mais chaque contrôle peut fournir sa propre fonction.
type Aggregate func([]HostAssessment) (cyfun.MaturityLevel, string)

// WorstCase retient le niveau le plus faible parmi les hôtes évalués : en
// sécurité, un seul endpoint non protégé compromet le parc. Les hôtes non
// évalués (NotAssessed) sont ignorés pour ne pas masquer un vrai résultat.
func WorstCase(has []HostAssessment) (cyfun.MaturityLevel, string) {
	worst := cyfun.NotAssessed
	found := false
	for _, ha := range has {
		if ha.ProposedImplLevel == cyfun.NotAssessed {
			continue
		}
		if !found || ha.ProposedImplLevel < worst {
			worst, found = ha.ProposedImplLevel, true
		}
	}
	if !found {
		return cyfun.NotAssessed, "Aucun hôte n'a pu être évalué."
	}
	return worst, "Niveau retenu = pire cas parmi les hôtes évalués (maillon faible)."
}

// ControlResult = résultat consolidé d'un contrôle pour l'audit : volet
// technique (par hôte + agrégat proposé), scores finaux, et traçabilité de
// l'override consultant.
type ControlResult struct {
	Meta cyfun.ControlMeta `json:"meta"`

	// Volet technique
	HostAssessments []HostAssessment    `json:"host_assessments,omitempty"`
	ProposedImpl    cyfun.MaturityLevel `json:"proposed_impl"` // agrégat des hôtes

	// Scores FINAUX (ce qui part au rapport). Documentation vient du
	// questionnaire ; Implementation vient du scan (proposé), éventuellement
	// corrigé par le consultant.
	FinalDoc  cyfun.MaturityLevel `json:"final_doc"`
	FinalImpl cyfun.MaturityLevel `json:"final_impl"`

	// Traçabilité de l'override (preuve d'audit)
	ImplOverridden bool   `json:"impl_overridden"`
	OverrideReason string `json:"override_reason,omitempty"`

	// ImplFromAttestation = true quand le scan n'a rien pu constater (hôte
	// injoignable, OS non supporté) et que l'Implementation a basculé sur
	// l'attestation du questionnaire (dégradation gracieuse). Preuve d'audit :
	// on distingue une valeur MESURÉE d'une valeur DÉCLARÉE de repli.
	ImplFromAttestation bool `json:"impl_from_attestation,omitempty"`

	// NotApplicable = contrôle marqué « non applicable » (attesté par le
	// consultant, avec justification dans OverrideReason). Comme dans le barème
	// CCB, sa maturité vaut le seuil Key Measure du niveau lors de l'agrégation :
	// il ne pénalise ni n'aide la conformité.
	NotApplicable bool `json:"not_applicable,omitempty"`
}

// Maturity = maturité du requirement selon la règle OFFICIELLE :
// moyenne(Documentation, Implementation).
func (r ControlResult) Maturity() cyfun.MaturityScore {
	return cyfun.MaturityScore(r.FinalDoc+r.FinalImpl) / 2
}

// Assessed indique si le contrôle a une maturité EXPLOITABLE : soit il est
// attesté non applicable, soit ses DEUX axes (Documentation ET Implementation)
// portent une valeur (> NotAssessed). Un contrôle où le scan n'a rien pu
// constater ET dont l'axe manquant n'a pas été attesté au questionnaire n'est
// PAS évalué : le noter 0 fabriquerait une fausse faille (contraire au principe
// d'intégrité), l'ignorer en silence cacherait un trou. On le signale donc comme
// « à évaluer » et il bloque le verdict de conformité tant qu'il n'est pas résolu.
func (r ControlResult) Assessed() bool {
	if r.NotApplicable {
		return true
	}
	return r.FinalDoc > cyfun.NotAssessed && r.FinalImpl > cyfun.NotAssessed
}

// ConformAt indique si le contrôle satisfait le seuil INDIVIDUEL donné. Ce
// seuil ne s'applique qu'aux Key Measures ; les autres contrôles ne sont pas
// bloquants individuellement (ils comptent dans la moyenne totale).
func (r ControlResult) ConformAt(kmThreshold cyfun.MaturityScore) bool {
	if !r.Meta.KeyMeasure {
		return true
	}
	return r.Maturity() >= kmThreshold
}

// ConformBasic = raccourci au seuil Basic (2,5). Conservé pour compatibilité.
func (r ControlResult) ConformBasic() bool {
	return r.ConformAt(cyfun.BasicKeyMeasureThreshold)
}
