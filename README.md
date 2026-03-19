🚀 WiFi Network Scanner PRO

CapCap est un outil Python conçu pour le reconnaissance réseau (network reconnaissance) lors de tests de sécurité légaux ou d'audits réseau.

Ce script permet de scanner un réseau local, détecter les machines actives et identifier les ports ouverts afin d'aider à l'analyse de la surface d'attaque d'un réseau.

⚠️ Cet outil est destiné uniquement à un usage éthique et légal, avec l'autorisation du propriétaire du réseau.

---

🔍 Fonctionnalités

📡 Détection automatique du réseau

- Détecte automatiquement l'adresse IP locale
- Détermine le réseau à scanner (ex : "192.168.1.0/24")

🖥 Découverte des machines actives

- Scan rapide des hôtes du réseau
- Détection via plusieurs ports communs
- Multi-threading pour accélérer le scan

🔓 Scan des ports

Analyse des ports courants comme :

- 21 (FTP)
- 22 (SSH)
- 23 (Telnet)
- 25 (SMTP)
- 53 (DNS)
- 80 (HTTP)
- 443 (HTTPS)
- 3306 (MySQL)
- 3389 (RDP)
- 5900 (VNC)
- 8080 (HTTP Proxy)
- 8443 (HTTPS Alt)

Le script détecte quels ports sont ouverts sur les machines actives.

🌐 Détection de serveur HTTP

Si un port "80" est ouvert :

- le script tente de récupérer la bannière HTTP
- exemple : "Apache", "nginx", etc.

📊 Rapport final

Le scanner affiche :

- nombre d'hôtes actifs
- ports ouverts par machine
- services probables

💾 Export JSON

Les résultats sont automatiquement sauvegardés dans un fichier JSON contenant :

- réseau scanné
- timestamp
- machines actives
- ports ouverts détectés

---

🧠 Objectif du script

Ce script permet de :

- identifier rapidement les machines connectées à un réseau
- repérer les services exposés
- préparer une analyse de sécurité plus approfondie

Les résultats peuvent ensuite être analysés avec des outils comme Nmap pour identifier les services et potentielles vulnérabilités.

---

⚡ Utilisation

Lancer simplement le script :

python3 CapCap.py

Le scanner va :

1. détecter le réseau local
2. scanner les hôtes actifs
3. analyser les ports ouverts
4. générer un rapport
5. sauvegarder les résultats en JSON

---

🛠 Technologies utilisées

- Python 3
- socket
- concurrent.futures (multi-threading)
- ipaddress
- JSON

---

📈 Roadmap

Version actuelle

- [x] Détection automatique du réseau
- [x] Scan des machines actives
- [x] Scan des ports principaux
- [x] Détection HTTP basique
- [x] Export JSON des résultats

Améliorations possibles

- [ ] Détection automatique des services (banner grabbing)
- [ ] Détection OS basique
- [ ] Mode scan rapide / mode discret
- [ ] Ajout d'un scan de ports étendu
- [ ] Rapport HTML
- [ ] Intégration avec outils d'analyse de vulnérabilités

---

⚠️ Avertissement légal

Ce projet est fourni à des fins éducatives et de recherche en cybersécurité.

L'utilisation de cet outil pour scanner un réseau sans autorisation peut être illégale.

L'utilisateur est seul responsable de l'utilisation de ce script.

---

👤 Auteur

Mr.Dark

Projet personnel d'apprentissage en cybersécurité et reconnaissance réseau.
![1000131064](https://github.com/user-attachments/assets/78bd42ad-1152-4394-b33b-dc19e4f48264)


https://github.com/user-attachments/assets/aa15e46e-8e52-4791-9154-e2ca244eba10

