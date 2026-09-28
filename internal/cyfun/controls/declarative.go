package controls

import (
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// DeclarativeControl = un contrôle organisationnel NON scannable : ses deux axes
// (Documentation et Implementation) viennent entièrement du questionnaire, car
// aucun scan hôte ne peut les constater. C'est le cas de la majorité des 34
// contrôles Basic (gouvernance, procédures, formation, sauvegardes, etc.).
type DeclarativeControl struct {
	Meta      cyfun.ControlMeta
	Questions []survey.Question
}

// decl fabrique un contrôle déclaratif avec une question Documentation et une
// question Implementation sur l'échelle de maturité standard. Réduit le
// catalogue de 29 contrôles à une ligne de DONNÉES par contrôle (texte officiel
// du CCB repris tel quel au rapport).
func decl(id string, fn cyfun.Function, cat, sub string, km bool, req, docQ, implQ string) DeclarativeControl {
	return declLevel(id, fn, cat, sub, cyfun.LevelBasic, km, req, docQ, implQ)
}

// declLevel est la variante avec niveau d'assurance explicite (Basic, Important…)
// — c'est le NIVEAU MINIMAL auquel le contrôle entre dans le périmètre.
func declLevel(id string, fn cyfun.Function, cat, sub, level string, km bool, req, docQ, implQ string) DeclarativeControl {
	return DeclarativeControl{
		Meta: cyfun.ControlMeta{
			ID: id, Function: fn, Category: cat, Subcategory: sub,
			Requirement: req, Level: level, KeyMeasure: km,
		},
		Questions: []survey.Question{
			survey.Ask(id, survey.Documentation, "doc", docQ),
			survey.Ask(id, survey.Implementation, "impl", implQ),
		},
	}
}

// impDecl : raccourci pour un contrôle du niveau IMPORTANT (voir important.go).
func impDecl(id string, fn cyfun.Function, cat, sub string, km bool, req, docQ, implQ string) DeclarativeControl {
	return declLevel(id, fn, cat, sub, cyfun.LevelImportant, km, req, docQ, implQ)
}

// essDecl : raccourci pour un contrôle du niveau ESSENTIAL (voir essential.go).
func essDecl(id string, fn cyfun.Function, cat, sub string, km bool, req, docQ, implQ string) DeclarativeControl {
	return declLevel(id, fn, cat, sub, cyfun.LevelEssential, km, req, docQ, implQ)
}

// DeclarativeControls = catalogue des contrôles déclaratifs Basic restants
// (hors GV.PO-01.1, défini à part, et hors contrôles scannables). Ajouté au
// registre par une boucle. Les textes de requirement sont ceux, exacts, du
// Self-Assessment tool CCB (onglets GOVERN…RECOVER).
var DeclarativeControls = []DeclarativeControl{
	// --- GOVERN ---
	decl("GV.OC-03.1", cyfun.Govern, "GV.OC", "GV.OC-03", false,
		"Legal and regulatory requirements regarding information and cybersecurity shall be identified and implemented.",
		"Les exigences légales et réglementaires en matière de sécurité de l'information sont-elles identifiées et documentées ?",
		"Sont-elles effectivement prises en compte et respectées dans les opérations ?"),
	decl("GV.RM-03.1", cyfun.Govern, "GV.RM", "GV.RM-03", false,
		"As part of the organisation-wide risk management strategy, a comprehensive strategy to manage information and cybersecurity risks shall be developed and updated when changes occur.",
		"Une stratégie de gestion des risques cyber est-elle formalisée et tenue à jour ?",
		"Est-elle réellement pilotée (revue lors des changements, décisions tracées) ?"),
	decl("GV.RR-04.1", cyfun.Govern, "GV.RR", "GV.RR-04", false,
		"Personnel with access to the organisation’s most critical information or technology shall be authenticated.",
		"Une règle impose-t-elle l'authentification du personnel accédant aux ressources les plus critiques ?",
		"Cette authentification est-elle effectivement en place pour ces accès ?"),

	// --- IDENTIFY ---
	decl("ID.AM-01.1", cyfun.Identify, "ID.AM", "ID.AM-01", false,
		"An inventory of physical and virtual infrastructure assets—such as hardware, network devices, and cloud-hosted environments—that support information processing shall be documented, reviewed, and updated as changes occur.",
		"Un inventaire des actifs d'infrastructure (matériel, réseau, cloud) est-il documenté ?",
		"Est-il tenu à jour et revu lors des changements ?"),
	// ID.AM-02.1 est désormais SCANNABLE (voir idam0201.go).
	decl("ID.AM-5.1", cyfun.Identify, "ID.AM", "ID.AM-05", false, // sous-catégorie ID.AM-05 (ID d'exigence tel qu'écrit par le CCB)
		"The organisation’s assets shall be prioritised based on classification, criticality, and business value.",
		"Les actifs sont-ils classifiés/priorisés (criticité, valeur métier) de façon documentée ?",
		"Cette priorisation est-elle réellement utilisée pour les décisions de sécurité ?"),
	decl("ID.AM-07.1", cyfun.Identify, "ID.AM", "ID.AM-07", false,
		"Data that the organisation stores and uses shall be identified.",
		"Les données stockées et traitées par l'organisation sont-elles identifiées et documentées ?",
		"Cette identification est-elle tenue à jour et exploitée ?"),
	decl("ID.RA-01.1", cyfun.Identify, "ID.RA", "ID.RA-01", false,
		"Threats and vulnerabilities shall be identified in all relevant assets, including software, network and system architectures, and facilities that house critical computing assets.",
		"Un processus d'identification des menaces et vulnérabilités est-il documenté ?",
		"Est-il exécuté régulièrement sur les actifs pertinents ?"),
	decl("ID.RA-05.1", cyfun.Identify, "ID.RA", "ID.RA-05", false,
		"The organisation shall conduct risk assessments in which risk is determined by threats, vulnerabilities and the impact on business processes and assets.",
		"Une méthode d'évaluation des risques (menace × vulnérabilité × impact) est-elle définie ?",
		"Des évaluations de risques sont-elles réellement menées et tracées ?"),
	decl("ID.IM-03.1", cyfun.Identify, "ID.IM", "ID.IM-03", false,
		"The organisation shall conduct post-incident evaluations to analyse lessons learned from incident response and recovery, and consequently improve processes / procedures / technologies to enhance its cyber-resilience.",
		"Une procédure de retour d'expérience post-incident est-elle documentée ?",
		"Des revues post-incident sont-elles effectivement conduites et suivies d'améliorations ?"),

	// --- PROTECT ---
	// PR.AA-01.1 est désormais SCANNABLE (voir praa0101.go).
	decl("PR.AA-03.1", cyfun.Protect, "PR.AA", "PR.AA-03", false,
		"All wireless access points used by the organisation, including those providing guest access, shall be securely configured, managed, and monitored to prevent unauthorised access and ensure network integrity.",
		"Les points d'accès Wi-Fi (y compris invités) font-ils l'objet de règles de configuration sécurisée documentées ?",
		"Sont-ils réellement configurés, gérés et surveillés en ce sens ?"),
	// PR.AA-03.2 est désormais SCANNABLE (voir praa0302.go) — preuve partielle.
	// PR.AA-05.1 est désormais SCANNABLE (voir praa0501.go) — preuve partielle.
	decl("PR.AA-05.2", cyfun.Protect, "PR.AA", "PR.AA-05", true,
		"It shall be determined who needs access to the organisation's business-critical information and technology and the means to gain access.",
		"Les besoins d'accès aux ressources critiques sont-ils formellement déterminés ?",
		"Les accès accordés correspondent-ils réellement à ces besoins ?"),
	// PR.AA-05.3 est désormais SCANNABLE (voir praa0503.go).
	// PR.AA-05.4 est désormais SCANNABLE (voir praa0504.go).
	decl("PR.AA-06.1", cyfun.Protect, "PR.AA", "PR.AA-06", false,
		"Physical access to all organisational assets, including critical zones, shall be managed, monitored, and enforced based on risk.",
		"Le contrôle des accès physiques (zones critiques comprises) est-il défini selon le risque ?",
		"Est-il réellement appliqué et surveillé ?"),
	decl("PR.AT-01.1", cyfun.Protect, "PR.AT", "PR.AT-01", false,
		"The organisation shall establish and maintain a cybersecurity awareness and training programme to ensure that all personnel understand how to perform their tasks securely and responsibly.",
		"Un programme de sensibilisation/formation à la cybersécurité est-il défini ?",
		"Est-il effectivement dispensé à l'ensemble du personnel ?"),
	decl("PR.DS-01.9", cyfun.Protect, "PR.DS", "PR.DS-01", false,
		"Enterprise assets shall be disposed of safely.",
		"Une procédure de mise au rebut sécurisée des actifs (effacement des données) existe-t-elle ?",
		"Est-elle appliquée lors des réformes/reventes de matériel ?"),
	// PR.DS-11.1 est désormais SCANNABLE (voir prds1101.go).
	// PR.PS-05.1 est désormais SCANNABLE (voir prps0501.go) — preuve partielle.
	// PR.IR-01.1 est désormais SCANNABLE (voir netdevice.go) : retiré du
	// catalogue déclaratif. Son volet Documentation reste dans le questionnaire.
	// PR.IR-01.2 est désormais SCANNABLE (voir prir0102.go).

	// --- DETECT ---
	// DE.CM-03-1 est désormais SCANNABLE (voir decm0301.go).
	// DE.AE-03.1 est désormais SCANNABLE (voir deae0301.go).

	// --- RESPOND ---
	decl("RS.MA-01.1", cyfun.Respond, "RS.MA", "RS.MA-01", false,
		"An incident response plan, including defined roles, responsibilities, and authorities, shall be executed during or after a cybersecurity event affecting the organisation's critical systems.",
		"Un plan de réponse aux incidents (rôles, responsabilités) est-il documenté ?",
		"Est-il connu et exécuté lors d'incidents réels ou d'exercices ?"),
	decl("RS.CO-02.1", cyfun.Respond, "RS.CO", "RS.CO-02", false,
		"Information about cybersecurity incidents shall be communicated to employees in a way that is clear and easy to understand.",
		"Des modalités de communication des incidents au personnel sont-elles prévues ?",
		"La communication est-elle réellement faite de façon claire lors des incidents ?"),

	// --- RECOVER ---
	decl("RC.RP-01.1", cyfun.Recover, "RC.RP", "RC.RP-01", false,
		"A recovery process for disasters and information/cybersecurity incidents shall be developed and executed.",
		"Un processus de reprise après sinistre/incident est-il développé et documenté ?",
		"Est-il testé et exécutable (restaurations vérifiées) ?"),
}
