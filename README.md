# 🛡️ Projet de Sécurisation : Déploiement d'un WAF ModSecurity avec Apache sur Debian Server

**Auteur :** Elif JAFFRES

> [!NOTE]
> Ce projet a été réalisé dans le cadre de mon apprentissage en cybersécurité et est documenté ici pour mon portfolio. 
> L'objectif principal est de démontrer l'application des principes de **défense en profondeur**. J'ai pour cela déployé un pare-feu applicatif (WAF) en production pour protéger un serveur web, puis j'ai développé une application web volontairement vulnérable pour illustrer concrètement l'intérêt de cette protection face à des attaques réelles.
>
> ⚠️ **Avertissement à but éducatif** : Toutes les techniques d'exploitation (Injections SQL, Bypass) documentées ci-dessous ont été réalisées dans un environnement de laboratoire strictement contrôlé et isolé.

Ce guide technique détaille, étape par étape, mon processus de réflexion, les commandes utilisées et les configurations appliquées pour mettre en place **ModSecurity** couplé à l'**OWASP Core Rule Set (CRS)** sur un serveur **Apache**.

---

##  1. Préparation de l'environnement de base

La première étape de toute politique de sécurité consiste à s'assurer que le système hôte est sain, à jour et restreint aux seuls services nécessaires. J'ai utilisé une machine virtuelle sous environnement Ubuntu/Debian.

### 1.1 Mise à jour du système d'exploitation
Une règle d'or en administration système est de travailler sur un système où toutes les vulnérabilités publiques connues (CVE) sont patchées.
```bash
# Met à jour la liste des paquets disponibles puis installe les dernières versions
sudo apt update && sudo apt upgrade -y
```
![Mise à jour et upgrade](images/sudoaptupdateupgrade.png)

### 1.2 Installation et gestion du service Apache2
J'ai choisi Apache comme serveur web (la pile logicielle sur laquelle le WAF viendra se greffer).

```bash
# Installation du paquet serveur web Apache
sudo apt install apache2 -y
```

Une fois installé, il est crucial de s'assurer du bon fonctionnement du service et de l'activer pour qu'il démarre automatiquement à chaque redémarrage du serveur.
```bash
# Vérifie la version installée
apache2 -v

# Active le démarrage automatique du service Apache
sudo systemctl enable apache2

# Vérifie l'état actuel du service (doit être "active (running)")
sudo systemctl status apache2
```
![Status Apache](images/apachaeinstalledansstatus.png)
![Enable Apache](images/sudosystemctlenableapache2.png)

### 1.3 Configuration du pare-feu avec UFW
La sécurité réseau de base (filtrage de ports) est assurée par `UFW` (Uncomplicated Firewall), une surcouche simplifiée pour `iptables`. L'objectif ici est d'appliquer le principe du moindre privilège en n'ouvrant que les flux stricts : le web et l'administration distante.

```bash
# Liste les profils d'applications connus par le pare-feu
sudo ufw app list

# Autorise le trafic HTTP (port 80) et HTTPS (port 443) via le profil Apache
sudo ufw allow 'Apache Full'

# Autorise l'accès SSH (port 22) pour l'administration distante
sudo ufw allow 'OpenSSH'

# Active le pare-feu système
sudo ufw enable

# Affiche l'état des règles actives
sudo ufw status
```
![Configuration UFW](images/ufwconfig.png)

---

## ⚙️ 2. Installation et paramétrage du moteur ModSecurity

ModSecurity agit comme un module intégré à Apache. Il inspecte à la volée tout le trafic HTTP entrant et sortant.

### 2.1 Déploiement du module
L'installation se fait directement depuis les dépôts officiels.
```bash
# Installe le module ModSecurity pour Apache
sudo apt install libapache2-mod-security2 -y

# Force l'activation du module dans la configuration d'Apache
sudo a2enmod security2

# Redémarre le service pour que le nouveau module soit pris en charge
sudo systemctl restart apache2
```
![Installation ModSecurity](images/installation-libapache2-mod-security2.png)

### 2.2 Configuration principale du moteur
ModSecurity est fourni avec un fichier de configuration recommandé contenant les bonnes pratiques de base. J'ai copié ce modèle pour créer ma configuration active.

```bash
# Création du fichier de configuration à partir du modèle recommandé
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
```

Dans ce fichier `/etc/modsecurity/modsecurity.conf`, plusieurs directives sont essentielles. Je les ai examinées et configurées avec soin :
- **`SecRuleEngine DetectionOnly`** : Dans un premier temps, j'ai laissé le moteur en mode détection pure. Cela permet au WAF de journaliser les attaques sans bloquer les utilisateurs légitimes, le temps d'observer le trafic et d'éviter les "faux positifs".
- **`SecAuditEngine On`** : Active la création de journaux d'audit complexes pour chaque transaction suspecte.
- **`SecRequestBodyAccess On`** : Demande au WAF d'analyser le corps des requêtes POST (fichiers, formulaires JSON). C'est là que se cachent 90% des attaques web.

![Configuration ModSecurity](images/modsecurity-conf.png)

---

##  3. Intégration de l'OWASP Core Rule Set (CRS)

ModSecurity sans règles, c'est comme un antivirus sans base de signatures. L'**OWASP CRS** est l'intelligence du système, un ensemble de règles génériques conçues pour contrer le Top 10 des vulnérabilités web (SQLi, XSS, Path Traversal...).

### 3.1 Téléchargement et structuration
Plutôt que d'utiliser des paquets obsolètes, j'ai récupéré la dernière version stable (v4.18.0) directement depuis le dépôt officiel.

```bash
# Définition de la variable de version
VERSION="v4.18.0" 

# Navigation dans le répertoire temporaire
cd /tmp

# Téléchargement de l'archive tar.gz du CRS
wget "https://github.com/coreruleset/coreruleset/archive/refs/tags/${VERSION}.tar.gz"

# Extraction de l'archive
tar -xzvf ${VERSION}.tar.gz

# Déplacement de l'archive extraite dans le dossier de configuration d'Apache
sudo mv coreruleset-${VERSION/v/} /etc/apache2/modsecurity-crs
```

### 3.2 Définition de la stratégie de sécurité (crs-setup.conf)
Le CRS utilise un fichier de configuration dédié pour définir son agressivité, appelé **Niveau de Paranoïa (Paranoia Level - PL)**.

```bash
cd /etc/apache2/modsecurity-crs
# Création du fichier de configuration CRS actif
sudo cp crs-setup.conf.example crs-setup.conf
```

J'ai édité ce fichier pour ajuster les comportements critiques :
1. **L'action par défaut (`SecDefaultAction`)** : J'ai confirmé la politique de l'Anomaly Scoring. Les requêtes sont évaluées, leur score de dangerosité s'accumule, et si le seuil est franchi, la requête est bloquée. 
![CRS Setup SecDefaultAction](images/crssetupconf-secdefaultaction-reglage.png)
![Changement vers log](images/secdefaultaction-chnageto-log.png)

2. **Le Paranoia Level (`SecAction id:900000`)** : J'ai activé le PL1, qui est la protection de base contre les attaques flagrantes, garantissant presque aucun faux positif sur un site standard.
![SecAction 900000 Paranoia Level](images/secaction-90000-active.png)

3. **La version du setup (`SecAction id:900990`)** : J'ai décommenté l'activation de la version du CRS (4.18.0) pour que le moteur sache quel ensemble de variables utiliser.
![SecAction 900990 Setup Version](images/secaction-990-active.png)

### 3.3 Liaison du CRS avec Apache
Il faut ensuite indiquer à Apache de charger ces nouvelles règles OWASP. J'ai ajouté ces directives dans le fichier `/etc/apache2/mods-enabled/security2.conf` :

![Configuration security2.conf](images/securty2conf-corrected.png)
*Cette capture montre l'inclusion de `crs-setup.conf` en premier lieu, suivi du dossier contenant les règles `rules/*.conf`.*

### 3.4 Adaptation aux contraintes matérielles (Bypass IP Strict)
Comme je travaille sur un environnement de test local (machine virtuelle) sans nom de domaine qualifié (FQDN), j'attaquais mon serveur via son adresse IP directe. Cependant, le CRS bloque par défaut ce comportement pour éviter l'énumération par des bots scanneurs.

J'ai donc dû éditer la règle spécifique **`REQUEST-920-PROTOCOL-ENFORCEMENT.conf`** :
![Accès via IP bloqué](images/ipvirtualmachine.png)
J'ai remplacé l'action `block` par `pass` au niveau de la règle `920350` ("Host header is a numeric IP address") afin d'autoriser mon trafic de test local.
![Edition règle Protocol Enforcement](images/secrule-edit-protocol-enforcement.png)

---

##  4. Vérification et Simulation d'attaques

Afin de confirmer que ma protection fonctionnait correctement (après avoir basculé le `SecRuleEngine` sur `On` pour bloquer les menaces), j'ai effectué une série de tests intrusifs.

### 4.1 Contrôle de syntaxe
Toujours valider la configuration d'Apache avant un rechargement pour éviter un crash du serveur en production :
```bash
# Vérifie la syntaxe des fichiers de conf Apache
sudo apache2ctl configtest

# Redémarre Apache si "Syntax OK" est retourné
sudo systemctl restart apache2
```
![Apache Config Test](images/apache2ctl-configtest.png)

### 4.2 Lancement de charges utiles (Payloads)
J'ai simulé des attaques courantes via l'outil système `curl` (qui permet de faire des requêtes HTTP personnalisées en ligne de commande). Le but était d'obtenir une réponse HTTP de blocage formel (**`403 Forbidden`**).

* **Test de Path Traversal (Exploration d'arborescence non autorisée)** :
  ```bash
  curl -i "http://<mon_ip>/?exec=/etc/passwd"
  ```
  Le serveur bloque instantanément la tentative de lecture de fichiers systèmes.
  ![Test Path Traversal](images/test-pathtraversal.png)

* **Test d'Injection SQL (Contournement de logique de base de données)** :
  J'ai envoyé un paramètre manipulé de façon à tromper une requête SQL.
  Résultat : Rejet immédiat par le WAF avec la page `403 Forbidden` standard d'Apache.
  ![Injection Rejetée](images/injection-rejected.png)

---

##  5. Maîtrise de la journalisation et analyse Forensique

En cybersécurité, bloquer c'est bien, comprendre c'est mieux. L'analyse des journaux (logs) permet de faire de la *Threat Intelligence* et d'ajuster finement le pare-feu.

### 5.1 Les deux logs essentiels
Je surveillais simultanément deux flux d'informations :
1. **Le "Signal" (`error.log`)** : Indique de manière concise qu'un incident a eu lieu, son type, et fournit un identifiant unique de transaction. J'utilise `tail -f` pour lire le journal en direct.
   ![Log Error Apache](images/injection-log-final.png)

2. **Le "Contexte complet" (`modsec_audit.log`)** : Une fois l'identifiant repéré, j'examine l'audit complet du WAF. Il détaille l'empreinte réseau, l'entête HTTP exact de l'attaquant, le corps de la requête, et précisément quelles règles du CRS ont "matché".
   J'ai documenté ici plusieurs étapes d'analyse de mes fichiers de logs :
   ![Log Audit ModSecurity 1](images/logtest1.png)
   ![Log Audit ModSecurity 2](images/logtest2.png)
   ![Log Audit ModSecurity 3](images/logtest3.png)
   ![Audit Log Détail 3 (Gros plan)](images/audotlogapprofondiedetest3.png)
   ![Log Audit ModSecurity 4](images/logtest4.png)

### 5.2 Création de règles d'exclusion personnalisées (Tuning)
Durant mes expériences, la mise en place d'un WAF a pu créer de rares cas où une requête légitime était considérée comme malveillante (Faux Positif). Plutôt que de désactiver la sécurité entière, j'ai créé un fichier d'exclusion pour affiner le chirurgien :

```bash
# Création d'un fichier d'exclusion lu avant les règles principales
sudo touch /etc/apache2/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
```
À l'intérieur, j'ai utilisé la directive `SecRuleRemoveById` pour désactiver des identifiants de règles très précis, uniquement sur certains périmètres, afin de fluidifier l'expérience utilisateur tout en maintenant la sécurité maximale.
![Règles d'exclusion](images/exclutionrules.png)

---

##  6. Démonstration pratique : Sécurisation d'une Application PHP/MariaDB Vulnérable

Pour prouver concrètement la valeur de cette infrastructure, j'ai codé de toutes pièces un site d'authentification présentant une faille critique.

### 6.1 Installation de la pile LAMP
J'ai complété mon serveur Apache par le moteur d'exécution PHP et une base de données MariaDB.
```bash
# Installation de MariaDB, PHP et des ponts de communication
sudo apt install mariadb-server php php-mysqli
```

Ensuite, depuis la console SQL (`sudo mariadb`), j'ai structuré la base de données : création de la table `utilisateurs`, d'un compte `lab_user` restreint à cette seule base (principe du moindre privilège), et d'un faux utilisateur de test `admin`.
![Création de l'utilisateur MariaDB](images/maridbcreateduser.png)

### 6.2 Développement du code vulnérable (CWE-89)
J'ai conçu un script d'authentification `index.php`. L'application est **intentionnellement vulnérable** car elle concatène la saisie utilisateur brute directement au sein de la syntaxe SQL, offrant une surface d'attaque directe sur le moteur de la base de données (absence de requêtes préparées `prepare()`).

Voici la vue du code et de l'interface en production :
![Code source index.php](images/indexphp.png)
![Vue Frontend ModSecurity](images/indexphpfronend-navigateur.png)

### 6.3 Exploitation des failles (Avant activation du WAF)

J'ai simulé le rôle d'un attaquant pour exploiter mon propre code vulnérable.

**A. Bypass de l'Authentification (Contournement classique)**
Dans le formulaire web, j'ai injecté ce payload dans le nom d'utilisateur : `' OR 1=1 -- -`
<img width="537" height="353" alt="image" src="https://github.com/user-attachments/assets/26b5be62-cb31-45cc-8bd1-f514ab89136a" />

*L'explication derrière l'attaque :*
Le script PHP construit cette requête : `SELECT * FROM utilisateurs WHERE username = '' OR '1'='1' AND password = '...'`
La condition `1=1` étant une vérité mathématique absolue résolue par la base de données, la vérification du mot de passe est annulée par les commentaires SQL (`--`). Je me connecte ainsi automatiquement au premier compte de la base de données, qui s'avère être généralement l'Administrateur !

**B. Attaque avancée par l'opérateur UNION (Exfiltration de données)**
Une fois le bypass maitrisé, j'ai automatisé une attaque plus dangereuse via `curl`. L'objectif était de forcer la base de données à me cracher les mots de passe hachés des autres utilisateurs !
L'opérateur SQL `UNION` permet d'attacher un deuxième tableau de résultats à la requête d'origine. Puisque ma table utilisateurs avait 3 colonnes, j'ai fait une requête avec 3 arguments factices `SELECT 1, password, 3` :

```bash
curl -s -X POST http://localhost/index.php \
     -d "log_username=personne' UNION SELECT 1, password, 3 FROM utilisateurs WHERE username='admin' #" \
     -d "log_password=nimportequoi" \
     -d "login=Connexion" | grep "Connexion RÉUSSIE"
```
Une fois le composant ModSecurity activé en mode blocage (`SecRuleEngine On`), ces deux redoutables types d'attaques sont instantanément stoppés, prouvant la puissance d'une solution de virtual-patching.

---

> **Conclusion:** 
> L'accomplissement de ce projet m'a conféré une vision holistique (globale) de la sécurisation des architectures applicatives. Des paramétrages système de pare-feu réseau, à l'analyse experte de journaux d'audit, jusqu'à la création et exploitation directe d'une faille web OWASP, je maîtrise désormais le cycle de vie complet garantissant l'intégrité et la disponibilité d'une application face à des acteurs malveillants.
