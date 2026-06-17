# Repair-DirtyAD

Script PowerShell d'**audit et de remédiation progressive d'un environnement Active Directory**.

Le script collecte l'état du domaine, recherche plusieurs mauvaises configurations courantes, génère des exports CSV et des rapports HTML, puis permet d'appliquer certaines corrections uniquement lorsque les paramètres correspondants sont explicitement utilisés.

> [!WARNING]
> Ce projet a été conçu principalement pour un **laboratoire, un environnement de test et un projet de documentation BAIS**. Avant toute utilisation en production, relisez le code, réalisez une sauvegarde de l'Active Directory et testez chaque action avec `-WhatIf`.

## Fonctionnalités

### Audit de l'état de santé Active Directory

- Exécution de `dcdiag` ;
- contrôle de la réplication avec `repadmin` ;
- identification des détenteurs des rôles FSMO avec `netdom` ;
- génération de journaux avant et après les actions correctives.

### Inventaire des objets AD

Le script exporte notamment :

- les utilisateurs ;
- les groupes ;
- les ordinateurs ;
- les unités d'organisation ;
- les stratégies de groupe disponibles.

### Recherche de mauvaises configurations

Le script détecte :

- les utilisateurs et ordinateurs inactifs ;
- les comptes désactivés ;
- les comptes dont le mot de passe n'expire jamais ;
- les comptes sans pré-authentification Kerberos ;
- les comptes utilisateurs possédant un SPN ;
- les utilisateurs et ordinateurs configurés avec une délégation non contrainte ;
- les membres des principaux groupes privilégiés ;
- les groupes vides ;
- les GPO ne contenant apparemment aucun paramètre.

### Actions correctives optionnelles

Selon les paramètres utilisés, le script peut :

- créer une OU de quarantaine ;
- désactiver les utilisateurs inactifs ;
- déplacer les utilisateurs inactifs dans l'OU de quarantaine ;
- désactiver les ordinateurs inactifs ;
- déplacer les ordinateurs inactifs dans l'OU de quarantaine ;
- réactiver la pré-authentification Kerberos ;
- désactiver l'option `PasswordNeverExpires` ;
- supprimer la délégation non contrainte ;
- désactiver les GPO détectées comme vides.

Par défaut, **aucune de ces corrections n'est appliquée**. Une exécution sans paramètre réalise uniquement l'audit et génère les rapports.

## Prérequis

- Windows Server ou poste Windows disposant des outils RSAT ;
- Windows PowerShell 5.1 recommandé ;
- module PowerShell `ActiveDirectory` ;
- module PowerShell `GroupPolicy` pour l'audit et la sauvegarde des GPO ;
- droits suffisants pour lire les objets du domaine ;
- droits d'administration du domaine pour les actions correctives concernées ;
- exécution depuis un contrôleur de domaine ou un serveur d'administration correctement configuré.

Pour vérifier la présence des modules :

```powershell
Get-Module -ListAvailable ActiveDirectory, GroupPolicy
```

## Installation

Clonez le dépôt :

```powershell
git clone https://github.com/VOTRE-UTILISATEUR/Repair-DirtyAD.git
cd Repair-DirtyAD
```

Vous pouvez également télécharger uniquement le fichier `Repair-DirtyAD.ps1`.

Selon la stratégie d'exécution PowerShell de votre environnement, il peut être nécessaire d'autoriser temporairement l'exécution du script dans la session courante :

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Utilisation

### Audit seul

```powershell
.\Repair-DirtyAD.ps1
```

Cette commande réalise l'audit sans appliquer de correction.

### Choisir le dossier de sortie

Le chemin prévu par défaut dans le script est :

```text
E:\Audit_AD
```

Il peut être remplacé au lancement :

```powershell
.\Repair-DirtyAD.ps1 -OutputRoot "C:\Audit_AD"
```

### Modifier le seuil d'inactivité

Le seuil par défaut est de 90 jours :

```powershell
.\Repair-DirtyAD.ps1 -InactiveDays 120
```

### Créer l'OU de quarantaine

```powershell
.\Repair-DirtyAD.ps1 -CreateQuarantineOU
```

### Simuler la désactivation et le déplacement des utilisateurs inactifs

```powershell
.\Repair-DirtyAD.ps1 `
    -CreateQuarantineOU `
    -DisableInactiveUsers `
    -MoveInactiveUsersToQuarantine `
    -WhatIf
```

### Simuler la désactivation et le déplacement des ordinateurs inactifs

```powershell
.\Repair-DirtyAD.ps1 `
    -CreateQuarantineOU `
    -DisableInactiveComputers `
    -MoveInactiveComputersToQuarantine `
    -WhatIf
```

### Simuler plusieurs corrections de sécurité

```powershell
.\Repair-DirtyAD.ps1 `
    -FixNoPreAuth `
    -FixUnconstrainedDelegation `
    -WhatIf
```

### Appliquer une correction après validation

```powershell
.\Repair-DirtyAD.ps1 -FixNoPreAuth
```

N'enlevez `-WhatIf` qu'après avoir examiné les exports, identifié les objets concernés et validé l'impact métier.

## Paramètres disponibles

| Paramètre | Description |
|---|---|
| `-OutputRoot` | Définit le dossier racine des rapports et des exports. |
| `-InactiveDays` | Définit le nombre de jours servant à identifier les comptes inactifs. |
| `-CreateQuarantineOU` | Crée l'OU de quarantaine si elle n'existe pas. |
| `-DisableInactiveUsers` | Désactive les utilisateurs considérés comme inactifs. |
| `-MoveInactiveUsersToQuarantine` | Déplace les utilisateurs inactifs dans l'OU de quarantaine. |
| `-DisableInactiveComputers` | Désactive les comptes ordinateurs inactifs. |
| `-MoveInactiveComputersToQuarantine` | Déplace les ordinateurs inactifs dans l'OU de quarantaine. |
| `-FixNoPreAuth` | Réactive la pré-authentification Kerberos. |
| `-FixPasswordNeverExpires` | Désactive l'option indiquant que le mot de passe n'expire jamais. |
| `-FixUnconstrainedDelegation` | Désactive la délégation non contrainte sur les objets détectés. |
| `-DisableEmptyGPOs` | Désactive les GPO détectées comme ne contenant aucun paramètre. |
| `-WhatIf` | Simule les actions correctives sans les appliquer. |

## Rapports générés

Chaque exécution crée un dossier horodaté :

```text
Audit_AD/
└── Run_YYYYMMDD_HHMMSS/
    ├── Exports/
    ├── GPO_Backup/
    ├── Logs/
    └── Rapports/
```

### `Exports`

Ce dossier contient les inventaires et constats au format CSV, par exemple :

- `users_inactive_90_days.csv` ;
- `users_disabled.csv` ;
- `users_password_never_expires.csv` ;
- `users_no_kerberos_preauth.csv` ;
- `users_with_spn.csv` ;
- `computers_inactive_90_days.csv` ;
- `users_unconstrained_delegation.csv` ;
- `computers_unconstrained_delegation.csv` ;
- `privileged_groups_members.csv` ;
- `empty_groups.csv` ;
- `gpo_full.csv` ;
- `gpo_empty_or_no_settings.csv`.

### `Logs`

Ce dossier contient notamment :

- la transcription PowerShell ;
- le journal des actions réalisées ;
- les résultats de `dcdiag` ;
- les résultats de `repadmin` ;
- la liste des rôles FSMO ;
- les rapports XML utilisés pour analyser les GPO.

### `GPO_Backup`

Lorsque le module `GroupPolicy` est disponible, le script tente d'effectuer une sauvegarde des GPO.

### `Rapports`

Ce dossier contient :

- un rapport HTML principal ;
- une synthèse CSV des constats ;
- un rapport HTML des GPO lorsque sa génération est possible.

## Précautions importantes

### Comptes inactifs

L'attribut `LastLogonDate` ne suffit pas toujours à déterminer qu'un compte est réellement inutilisé. Un compte de service, une machine rarement connectée ou un objet récemment créé peut être classé comme inactif.

Examinez toujours les fichiers CSV avant toute désactivation ou mise en quarantaine.

### Comptes avec SPN

Un compte possédant un SPN peut être associé à un service légitime. Le script les signale comme potentiellement exposés au Kerberoasting, mais ne les modifie pas automatiquement.

### `PasswordNeverExpires`

Certains comptes de service historiques peuvent dépendre de cette configuration. La désactiver sans préparation peut provoquer une interruption de service.

### Délégation non contrainte

La délégation non contrainte représente un risque important, mais elle peut encore être utilisée par certaines applications anciennes. Vérifiez les dépendances avant correction.

### GPO vides

Une GPO apparemment vide peut toujours avoir une utilité liée à son historique, ses permissions, son filtrage ou son intégration dans un processus d'administration. Ne la désactivez pas sans validation.

### Données sensibles

Les rapports générés peuvent contenir :

- le nom du domaine ;
- les noms des utilisateurs et des ordinateurs ;
- les groupes privilégiés ;
- les chemins LDAP ;
- des informations sur les GPO et la réplication.

**Ne publiez jamais les rapports issus d'un environnement réel dans un dépôt public.**

## Limites connues

- Le script ne remplace pas un audit de sécurité complet ;
- il n'analyse pas l'ensemble des ACL sensibles de l'Active Directory ;
- il ne détecte pas tous les chemins d'attaque possibles ;
- il ne remplace pas des outils spécialisés comme PingCastle, Purple Knight ou BloodHound ;
- la détection des GPO vides repose sur leur rapport XML et doit être confirmée manuellement ;
- les groupes privilégiés sont recherchés à partir de leurs noms standards en anglais, ce qui peut nécessiter une adaptation selon la langue du domaine ;
- les résultats dépendent des droits du compte utilisé et de la disponibilité des outils RSAT.

## Recommandations avant utilisation en production

1. Effectuer une sauvegarde récente et testée de l'Active Directory ;
2. exécuter le script une première fois en audit seul ;
3. analyser tous les fichiers CSV ;
4. documenter les exceptions et les comptes de service ;
5. tester les corrections avec `-WhatIf` ;
6. appliquer une seule catégorie de correction à la fois ;
7. contrôler la réplication et les services après chaque modification ;
8. conserver les journaux produits par le script.

## Contexte du projet

Ce script a été réalisé dans le cadre d'un travail de laboratoire et de documentation autour de l'audit et du durcissement d'un environnement Active Directory.

Il vise à fournir un support lisible et reproductible pour :

- inventorier un domaine ;
- identifier plusieurs configurations à risque ;
- documenter les constats ;
- simuler des remédiations ;
- conserver une trace des actions réalisées.

## Auteur

**Thagvi**

Développement réalisé avec assistance et relecture technique.

## Licence

Ce projet peut être distribué sous licence MIT. Ajoutez un fichier `LICENSE` au dépôt avant publication si vous souhaitez autoriser sa réutilisation, sa modification et sa redistribution selon les conditions de cette licence.

## Avertissement

Ce script est fourni sans garantie. L'auteur ne pourra être tenu responsable d'une interruption de service, d'une perte de données ou d'une modification non souhaitée provoquée par son utilisation.
