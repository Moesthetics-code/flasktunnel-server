# FlaskTunnel Client

**Alternative gratuite et open-source à ngrok** pour créer des tunnels HTTP sécurisés vers vos applications locales.

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://pypi.org/project/flasktunnel-client/)
[![Python](https://img.shields.io/badge/python-3.7+-brightgreen.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 🚀 Installation

```bash
# Via pip
pip install flasktunnel-client

# Via git (version développement)
pip install git+https://github.com/flasktunnel/client.git
```

## 🌟 Fonctionnalités

- ✅ **Tunnels HTTP/HTTPS sécurisés** vers localhost
- 🎯 **Sous-domaines personnalisés** (ex: `monapp.flasktunnel.dev`)
- 🔐 **Protection par mot de passe** optionnelle
- ⏰ **Durées configurables** (1h à 24h)
- 🌐 **Support CORS automatique**
- 📡 **Mode webhook** pour intégrations
- 🏠 **Mode local** pour développement
- 📊 **Monitoring en temps réel**
- 🎨 **Interface CLI moderne** avec Rich

## 🎯 Usage Rapide

### Commande basique
```bash
# Exposer le port 3000 avec un sous-domaine auto-généré
flasktunnel --port 3000
```

### Avec sous-domaine personnalisé
```bash
# Créer un tunnel avec sous-domaine spécifique
flasktunnel --port 5000 --subdomain monapp
# → Accessible via: https://monapp.flasktunnel.dev
```

## 📋 Table des Matières

- [Commandes CLI](#-commandes-cli)
- [Options Avancées](#-options-avancées)
- [Authentification](#-authentification)
- [Configuration](#-configuration)
- [Usage Programmatique](#-usage-programmatique)
- [Variables d'Environnement](#-variables-denvironnement)
- [Exemples Pratiques](#-exemples-pratiques)
- [Troubleshooting](#-troubleshooting)

## 🛠 Commandes CLI

### Créer un Tunnel

#### Tunnel basique
```bash
# Port spécifique
flasktunnel --port 8000

# Port + sous-domaine
flasktunnel --port 3000 --subdomain myapp

# Alias pour --subdomain
flasktunnel --port 3000 --name myapp
```

#### Tunnel sécurisé
```bash
# Avec mot de passe
flasktunnel --port 5000 --password monsecret

# HTTPS forcé
flasktunnel --port 443 --https

# Avec CORS activé
flasktunnel --port 3000 --cors
```

#### Durées personnalisées
```bash
# 1 heure (par défaut: 2h)
flasktunnel --port 3000 --duration 1h

# 24 heures (maximum)
flasktunnel --port 3000 --duration 24h

# Durées disponibles: 1h, 2h, 4h, 8h, 12h, 24h
```

#### Mode webhook
```bash
# Pour webhooks (durée étendue)
flasktunnel --port 4000 --webhook
```

### Gestion des Tunnels

#### Lister les tunnels actifs
```bash
flasktunnel --list
```

#### Tester la connexion
```bash
flasktunnel --test
```

#### Diagnostic du système
```bash
flasktunnel --diagnose
```

### Mode Développement

#### Mode local (serveur local sur port 8080)
```bash
flasktunnel --local-mode --port 3000
```

#### Serveur personnalisé
```bash
flasktunnel --server-url http://monserveur.com --port 3000
```

#### Mode verbeux
```bash
# Afficher toutes les requêtes en temps réel
flasktunnel --port 3000 --verbose
```

## 🔐 Authentification

### Créer un compte
```bash
flasktunnel --register
```

### Se connecter
```bash
flasktunnel --login
```

### Se déconnecter
```bash
flasktunnel --logout
```

### Utiliser une clé API
```bash
# Via argument
flasktunnel --auth MA_CLE_API --port 3000

# Via variable d'environnement
export FLASKTUNNEL_API_KEY="ma_cle_api"
flasktunnel --port 3000
```

## ⚙️ Options Avancées

### Commande complète avec toutes les options
```bash
flasktunnel \
  --port 3000 \
  --subdomain monapp \
  --password secret123 \
  --duration 4h \
  --cors \
  --https \
  --webhook \
  --auth MA_CLE_API \
  --verbose
```

### Configuration personnalisée
```bash
# Utiliser un fichier de config spécifique
flasktunnel --config ./ma-config.json --port 3000
```

## 📁 Configuration

### Fichier de configuration (.flasktunnel.json)

Créez un fichier `.flasktunnel.json` dans votre projet :

```json
{
  "port": 3000,
  "subdomain": "monapp",
  "duration": "4h",
  "cors": true,
  "https": false,
  "password": "monsecret",
  "webhook": false,
  "server_url": "https://flasktunnel.dev",
  "local_mode": false
}
```

### Configuration par projet
```bash
# Dans le dossier de votre projet
echo '{
  "port": 3000,
  "subdomain": "monprojet",
  "cors": true,
  "duration": "8h"
}' > .flasktunnel.json

# Puis simplement :
flasktunnel
```

### Fichier d'authentification (~/.flasktunnel/credentials.json)

Stockage automatique des identifiants après connexion :

```json
{
  "api_key": "ft_1234567890abcdef",
  "user_id": "user_123",
  "email": "mon@email.com",
  "plan": "free"
}
```

## 🔧 Variables d'Environnement

### Variables principales
```bash
# Configuration de base
export FLASKTUNNEL_PORT=3000
export FLASKTUNNEL_SUBDOMAIN=monapp
export FLASKTUNNEL_DURATION=4h

# Authentification
export FLASKTUNNEL_API_KEY=ma_cle_api
export FLASKTUNNEL_AUTH_TOKEN=mon_token

# Sécurité
export FLASKTUNNEL_PASSWORD=monsecret
export FLASKTUNNEL_CORS=true
export FLASKTUNNEL_HTTPS=true

# Mode développement
export FLASKTUNNEL_LOCAL_MODE=true
export FLASKTUNNEL_SERVER_URL=http://localhost:8080

# Webhook
export FLASKTUNNEL_WEBHOOK=true
export FLASKTUNNEL_CUSTOM_DOMAIN=mondomaine.com
```

### Exemple avec .env
```bash
# Créer un fichier .env
cat > .env << EOF
FLASKTUNNEL_PORT=5000
FLASKTUNNEL_SUBDOMAIN=devapp
FLASKTUNNEL_CORS=true
FLASKTUNNEL_DURATION=8h
FLASKTUNNEL_API_KEY=ft_votre_cle_ici
EOF

# Charger et utiliser
source .env
flasktunnel
```

## 💻 Usage Programmatique

### Exemple basique
```python
from flasktunnel import FlaskTunnelClient

# Créer un client
client = FlaskTunnelClient()

# Créer un tunnel
tunnel = client.create_tunnel(port=3000)
print(f"URL publique: {tunnel.public_url}")

# Attendre que le tunnel expire
tunnel.wait_until_expired()
```

### Exemple avancé
```python
from flasktunnel import FlaskTunnelClient, FlaskTunnelConfig

# Configuration personnalisée
config = FlaskTunnelConfig(
    port=5000,
    subdomain="monapp",
    password="secret123",
    duration="4h",
    cors=True,
    https=True
)

# Client avec configuration
client = FlaskTunnelClient(config)

# Créer le tunnel
tunnel = client.create_tunnel(
    port=config.port,
    subdomain=config.subdomain,
    password=config.password,
    duration=config.duration,
    cors=config.cors,
    https=config.https
)

# Callbacks pour les événements
def on_request(data):
    print(f"Requête reçue: {data['method']} {data['path']}")

def on_error(data):
    print(f"Erreur: {data['message']}")

tunnel.on('request', on_request)
tunnel.on('error', on_error)

# Connecter le WebSocket
tunnel.connect_websocket()

print(f"✅ Tunnel actif: {tunnel.public_url}")
tunnel.wait_until_expired()
```

### Gestion des tunnels
```python
from flasktunnel import FlaskTunnelClient

client = FlaskTunnelClient()

# Lister les tunnels
tunnels = client.list_tunnels()
for tunnel in tunnels:
    print(f"- {tunnel['public_url']} (port {tunnel['port']})")

# Supprimer un tunnel
tunnel_id = "tunnel_123456"
client.delete_tunnel(tunnel_id)

# Statistiques d'un tunnel
stats = client.get_tunnel_stats(tunnel_id)
if stats:
    print(f"Requêtes: {stats['requests_count']}")
    print(f"Trafic: {stats['bandwidth_used']}")
```

### Configuration depuis fichier
```python
from flasktunnel import FlaskTunnelConfig, FlaskTunnelClient

# Charger depuis fichier JSON
config = FlaskTunnelConfig.from_file("ma-config.json")

# Charger depuis variables d'environnement
config = FlaskTunnelConfig.from_env()

# Combiner fichier + arguments
config = FlaskTunnelConfig.from_file().merge_with_args(
    port=8000,
    subdomain="override"
)

client = FlaskTunnelClient(config)
```

## 🌍 Exemples Pratiques

### 1. Application Flask
```python
# app.py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello World depuis Flask!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

```bash
# Terminal 1: Démarrer Flask
python app.py

# Terminal 2: Exposer via FlaskTunnel
flasktunnel --port 5000 --subdomain flask-demo
```

### 2. Application Django
```bash
# Démarrer Django
python manage.py runserver 8000

# Exposer avec CORS pour les APIs
flasktunnel --port 8000 --subdomain django-api --cors
```

### 3. Server de développement Node.js
```bash
# Démarrer l'app Node
npm start  # suppose port 3000

# Tunnel avec monitoring en temps réel
flasktunnel --port 3000 --subdomain node-app --verbose
```

### 4. Webhook pour GitHub
```bash
# Serveur webhook local sur port 4000
flasktunnel --port 4000 --subdomain github-webhook --webhook --password secret123
```

### 5. API avec authentification
```bash
# API protégée
flasktunnel --port 8080 --subdomain secure-api --password api-secret --https --cors
```

### 6. Développement mobile (React Native, etc.)
```bash
# Serveur de dev accessible pour mobile
flasktunnel --port 19006 --subdomain expo-app --cors --duration 8h
```

## 🔍 Troubleshooting

### Diagnostic automatique
```bash
# Analyser les problèmes potentiels
flasktunnel --diagnose
```

### Problèmes courants

#### 1. Port non disponible
```bash
# Erreur: "Aucun service ne tourne sur le port 3000"
# Solutions:
python -m http.server 3000  # Serveur test
# ou
flasktunnel --port 8000  # Autre port
```

#### 2. Serveur inaccessible
```bash
# Tester la connexion
flasktunnel --test

# Mode local si serveur principal indisponible
flasktunnel --local-mode --port 3000
```

#### 3. Authentification
```bash
# Vérifier le statut de connexion
flasktunnel --login

# Ou utiliser clé API directement
flasktunnel --auth YOUR_API_KEY --port 3000
```

#### 4. Sous-domaine occupé
```bash
# Erreur: "Sous-domaine déjà utilisé"
# Solutions:
flasktunnel --port 3000 --subdomain monapp-v2
# ou laisser auto-générer:
flasktunnel --port 3000
```

### Logs et debugging
```bash
# Mode verbeux pour voir toutes les requêtes
flasktunnel --port 3000 --verbose

# Tester avec un serveur simple
python -c "
import http.server
import socketserver

PORT = 8000
Handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(('', PORT), Handler) as httpd:
    print(f'Server running on port {PORT}')
    httpd.serve_forever()
" &

flasktunnel --port 8000 --verbose
```

## 🛡️ Sécurité

### Bonnes pratiques
```bash
# Toujours utiliser un mot de passe pour les données sensibles
flasktunnel --port 3000 --password "mon-mot-de-passe-fort"

# Forcer HTTPS pour les APIs
flasktunnel --port 8080 --https --password secret

# Limiter la durée pour les tests temporaires
flasktunnel --port 3000 --duration 1h
```

### Protection des credentials
```bash
# Fichier de credentials protégé (600)
chmod 600 ~/.flasktunnel/credentials.json

# Variables d'environnement sécurisées
export FLASKTUNNEL_API_KEY="$(cat ~/.flasktunnel/api_key)"
```

## 📊 Monitoring et Stats

### Interface temps réel
```bash
# Monitoring complet avec stats
flasktunnel --port 3000 --verbose
```

### Stats programmatiques
```python
from flasktunnel import FlaskTunnelClient

client = FlaskTunnelClient()
tunnel = client.create_tunnel(port=3000)

# Récupérer les stats périodiquement
import time
while tunnel.is_active:
    stats = client.get_tunnel_stats(tunnel.tunnel_id)
    if stats:
        print(f"Requêtes: {stats['requests_count']}")
        print(f"Bande passante: {stats['bandwidth_used']}")
    time.sleep(60)
```

## 🤝 Support et Contribution

### Liens utiles
- 🌐 Site web: [https://flasktunnel.dev](https://flasktunnel.dev)
- 📚 Documentation: [https://docs.flasktunnel.dev](https://docs.flasktunnel.dev)
- 🐛 Issues: [https://github.com/flasktunnel/client/issues](https://github.com/flasktunnel/client/issues)
- 💬 Support: support@flasktunnel.dev

### Alternative si FlaskTunnel est indisponible
```bash
# Autres solutions de tunneling
# ngrok (payant après limite)
ngrok http 3000

# localtunnel (gratuit)
npx localtunnel --port 3000

# serveo (SSH tunnel)
ssh -R 80:localhost:3000 serveo.net
```

## 📄 License

MIT License - voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

**FlaskTunnel** - Rendez vos applications locales accessibles au monde entier ! 🚀