# Étude de sécurité Open Bastion — EBIOS Risk Manager

Cette étude suit la méthode **EBIOS Risk Manager** (ANSSI, 2018). Elle porte sur
la cible de sécurité maximale d'Open Bastion (Mode E) et **inclut le portail
LemonLDAP::NG et ses quatre plugins** dans son périmètre.

Les documents sont en français ; les documentations techniques auxquelles ils
renvoient (`doc/hardening.md`, `doc/audit.md`, `doc/pam-modes.md`) sont en
anglais.

## Plan de lecture

| Atelier                         | Document                                                                                                                       | Contenu                                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| —                               | [00-architecture.md](00-architecture.md)                                                                                       | Cible de sécurité, architecture, mécanismes de défense                                                              |
| **1** — Cadrage et socle        | [04-atelier1-cadrage-socle.md](04-atelier1-cadrage-socle.md)                                                                   | Périmètre, valeurs métier, biens supports, **échelles**, événements redoutés, socle                                 |
| **2** — Sources de risque       | [05-atelier2-sources-de-risque.md](05-atelier2-sources-de-risque.md)                                                           | Sources de risque, objectifs visés, couples SR/OV retenus                                                           |
| **3** — Scénarios stratégiques  | [06-atelier3-scenarios-strategiques.md](06-atelier3-scenarios-strategiques.md)                                                 | Écosystème, niveaux de menace, sept scénarios stratégiques                                                          |
| **4** — Scénarios opérationnels | [01-enrollment.md](01-enrollment.md) · [02-ssh-connection.md](02-ssh-connection.md) · [09-portail-llng.md](09-portail-llng.md) | **47 fiches de risque** avec scores initiaux et résiduels, matrices — dont huit pour le portail LLNG et ses plugins |
| **5** — Traitement              | [07-plan-de-traitement.md](07-plan-de-traitement.md) · [99-risk-reduce.md](99-risk-reduce.md)                                  | Plan de traitement daté et porté ; matrice résiduelle consolidée et argumentaire                                    |
| Décision                        | [08-dossier-homologation.md](08-dossier-homologation.md)                                                                       | Périmètre d'homologation, **conditions d'emploi**, acceptation des résiduels                                        |
| Opérationnel                    | [03-offboarding.md](03-offboarding.md)                                                                                         | Procédure de révocation des accès administrateurs                                                                   |

## Deux lectures utiles selon le besoin

- **« Puis-je déployer ce produit ? »** → lire les **conditions d'emploi** en
  [08-dossier-homologation.md, §2](08-dossier-homologation.md#2-conditions-demploi).
  Ce sont les quinze hypothèses que les scores résiduels supposent vérifiées, et
  que le produit n'impose pas toutes.
- **« Quel est le risque résiduel ? »** → lire la matrice consolidée en tête de
  [99-risk-reduce.md](99-risk-reduce.md), puis les trois risques en zone orange
  en [08, §3.1](08-dossier-homologation.md#31-zone-orange-acceptation-requise).

## Cohérence vérifiée mécaniquement

Une matrice de risque n'est pas une affirmation autonome : chaque case doit
découler du couple (Vraisemblance, Gravité) écrit dans la fiche correspondante.
`tests/ebios_matrix_check.py` — exécuté en CI par
`tests/test_ob_ebios_matrices.sh` — le vérifie et échoue si :

- une case de matrice contredit sa fiche ;
- un risque analysé manque à une matrice, ou y figure sans fiche ;
- un score répété dans un titre de section de `99-risk-reduce.md` contredit sa fiche ;
- une fiche n'est rattachée à aucun événement redouté de l'atelier 1 ;
- une liste de zone de risque ne découle pas des scores.

## État du dossier

Le dossier d'homologation porte des champs `À COMPLÉTER` : version du produit
visée, porteurs, échéances, décisions d'acceptation et signature. Ces valeurs
relèvent de l'autorité d'homologation et ne sont pas déduites de l'analyse. Tant
qu'ils subsistent, **le dossier est complet en tant qu'analyse, mais non signé.**
