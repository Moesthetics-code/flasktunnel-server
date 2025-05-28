import eventlet
eventlet.monkey_patch()

import os
import time
import uuid
import secrets
import hashlib
import threading
import warnings
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

import bcrypt
import requests
from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from sqlalchemy import inspect

from urllib.parse import urlparse

# Au début du fichier, après les imports
import os
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

if os.getenv('RAILWAY_ENVIRONMENT_NAME'):
    # Configuration spéciale pour Railway
    os.environ.setdefault('SQLALCHEMY_SILENCE_UBER_WARNING', '1')
    
    # Fix pour les variables Railway
    if not os.getenv('DATABASE_URL') and os.getenv('RAILWAY_POSTGRES_URL'):
        os.environ['DATABASE_URL'] = os.getenv('RAILWAY_POSTGRES_URL')

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    
    # Détecter l'environnement Railway
    is_railway = bool(os.getenv('RAILWAY_ENVIRONMENT_NAME'))
    is_production = os.getenv('FLASK_ENV') == 'production'
    
    
    # Configuration base de données pour Railway
    if is_railway:
        # Sur Railway : utiliser DATABASE_URL fourni automatiquement
        database_url = os.getenv('DATABASE_URL') or os.getenv('DATABASE_PRIVATE_URL')
        if database_url and database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        
        SQLALCHEMY_DATABASE_URI = database_url
        print(f"🚄 Railway environment detected")
        print(f"📊 Database: PostgreSQL - {database_url[:50]}...")
    else:
        # En local : utiliser SQLite ou variable custom
        SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///flaskserver.db')
        print("🏠 Local environment detected")
        print(f"📊 Database: {SQLALCHEMY_DATABASE_URI.split('://')[0]}")

# Supprimer les warnings
warnings.filterwarnings("ignore", message="Using the in-memory storage for tracking rate limits")

# =============================================================================
# Configuration
# =============================================================================

app = Flask(__name__)
app.config.from_object(Config)

# CORS Configuration
CORS(app, origins=["*"], allow_headers=["*"], methods=["*"])

# Database
db = SQLAlchemy(app)

# SocketIO - Configuration optimisée pour Railway
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    logger=False, 
    engineio_logger=False,
    async_mode='eventlet',
    ping_timeout=60,
    ping_interval=25,
    transports=['websocket', 'polling']
)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour", "100 per minute"],
    storage_uri="memory://"  # Spécifier explicitement le stockage en mémoire
)

# =============================================================================
# Models
# =============================================================================

class User(db.Model):
    """Modèle utilisateur."""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    plan = db.Column(db.String(20), default='free')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relations
    tunnels = db.relationship('Tunnel', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __init__(self, email: str, password: str):
        self.email = email.lower().strip()
        self.set_password(password)
        self.api_key = self.generate_api_key()
    
    def set_password(self, password: str) -> None:
        """Hasher le mot de passe."""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password: str) -> bool:
        """Vérifier le mot de passe."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def generate_api_key(self) -> str:
        """Générer une nouvelle clé API."""
        return secrets.token_hex(32)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'user_id': self.id,
            'email': self.email,
            'plan': self.plan,
            'created_at': self.created_at.isoformat(),
            'tunnel_count': self.tunnels.count()
        }


class Tunnel(db.Model):
    """Modèle tunnel."""
    __tablename__ = 'tunnels'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tunnel_id = db.Column(db.String(16), unique=True, nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    
    # Configuration du tunnel
    subdomain = db.Column(db.String(50), unique=True, nullable=False, index=True)
    port = db.Column(db.Integer, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    
    # URLs
    public_url = db.Column(db.String(255), nullable=False)
    
    # Paramètres
    cors_enabled = db.Column(db.Boolean, default=False)
    https_enabled = db.Column(db.Boolean, default=False)
    webhook_mode = db.Column(db.Boolean, default=False)
    
    # Métadonnées
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Statistiques
    requests_count = db.Column(db.Integer, default=0)
    bytes_transferred = db.Column(db.BigInteger, default=0)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.tunnel_id:
            self.tunnel_id = self.generate_tunnel_id()
        if not self.public_url:
            # Utiliser le domaine Railway au lieu de flasktunnel.dev
            base_domain = os.getenv('RAILWAY_STATIC_URL', '').replace('https://', '').replace('http://', '')
            if base_domain:
                self.public_url = f"https://{base_domain}/{self.subdomain}"
            else:
                self.public_url = f"http://localhost:8080/{self.subdomain}"
    
    def generate_tunnel_id(self) -> str:
        """Générer un ID de tunnel unique."""
        return secrets.token_urlsafe(8)
    
    def set_password(self, password: str) -> None:
        """Définir un mot de passe pour le tunnel."""
        if password:
            self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password: str) -> bool:
        """Vérifier le mot de passe du tunnel."""
        if not self.password_hash:
            return True
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    @property
    def is_expired(self) -> bool:
        """Vérifier si le tunnel a expiré."""
        return datetime.utcnow() > self.expires_at
    
    @property
    def remaining_time(self) -> int:
        """Temps restant en secondes."""
        remaining = (self.expires_at - datetime.utcnow()).total_seconds()
        return max(0, int(remaining))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'tunnel_id': self.tunnel_id,
            'subdomain': self.subdomain,
            'public_url': self.public_url,
            'port': self.port,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'expires_in': self.remaining_time,
            'password_protected': bool(self.password_hash),
            'cors_enabled': self.cors_enabled,
            'https_enabled': self.https_enabled,
            'webhook_mode': self.webhook_mode,
            'requests_count': self.requests_count,
            'bytes_transferred': self.bytes_transferred,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None
        }


# =============================================================================
# Services
# =============================================================================

class TunnelService:
    """Service de gestion des tunnels."""
    
    def __init__(self, app_instance):
        self.app = app_instance
        self.active_tunnels: Dict[str, Dict] = {}
        self.cleanup_running = True
        self.db_initialized = False
    
    def start_cleanup_thread(self):
        """Démarrer le thread de nettoyage après l'initialisation de la DB."""
        if not hasattr(self, 'cleanup_thread') or not self.cleanup_thread.is_alive():
            self.cleanup_thread = threading.Thread(target=self._cleanup_expired_tunnels, daemon=True)
            self.cleanup_thread.start()
            print("✅ Cleanup thread started")
    
    def _cleanup_expired_tunnels(self):
        """Nettoyer les tunnels expirés."""
        while not self.db_initialized and self.cleanup_running:
            time.sleep(1)
        
        while self.cleanup_running:
            try:
                with self.app.app_context():
                    try:
                        inspector = inspect(db.engine)
                        if 'tunnels' not in inspector.get_table_names():
                            time.sleep(5)
                            continue
                    except Exception:
                        time.sleep(5)
                        continue
                    
                    expired_tunnels = Tunnel.query.filter(
                        Tunnel.expires_at < datetime.utcnow(),
                        Tunnel.status == 'active'
                    ).all()
                    
                    for tunnel in expired_tunnels:
                        tunnel.status = 'expired'
                        if tunnel.tunnel_id in self.active_tunnels:
                            del self.active_tunnels[tunnel.tunnel_id]
                        
                        try:
                            socketio.emit('tunnel_expired', {
                                'tunnel_id': tunnel.tunnel_id,
                                'message': 'Tunnel expired'
                            }, room=f"tunnel_{tunnel.tunnel_id}")
                        except Exception:
                            pass
                    
                    if expired_tunnels:
                        db.session.commit()
                        print(f"🧹 Cleaned {len(expired_tunnels)} expired tunnels")
                
            except Exception as e:
                print(f"❌ Error in cleanup: {e}")
            
            time.sleep(60)
    
    def stop_cleanup(self):
        """Arrêter le thread de nettoyage."""
        self.cleanup_running = False
    
    def mark_db_initialized(self):
        """Marquer la DB comme initialisée."""
        self.db_initialized = True
        self.start_cleanup_thread()
    
    def create_tunnel(self, **kwargs) -> Tunnel:
        """Créer un nouveau tunnel."""
        tunnel = Tunnel(**kwargs)
        db.session.add(tunnel)
        db.session.commit()
        
        self.active_tunnels[tunnel.tunnel_id] = {
            'tunnel': tunnel,
            'proxy_thread': None,
            'created_at': time.time()
        }
        
        return tunnel
    
    def get_tunnel(self, tunnel_id: str) -> Optional[Tunnel]:
        """Récupérer un tunnel par ID."""
        return Tunnel.query.filter_by(tunnel_id=tunnel_id).first()
    
    def delete_tunnel(self, tunnel_id: str) -> bool:
        """Supprimer un tunnel."""
        tunnel = self.get_tunnel(tunnel_id)
        if tunnel:
            tunnel.status = 'deleted'
            if tunnel_id in self.active_tunnels:
                del self.active_tunnels[tunnel_id]
            db.session.commit()
            return True
        return False

tunnel_service = TunnelService(app)

# =============================================================================
# Utilities
# =============================================================================

def get_user_from_token(token: str) -> Optional[User]:
    """Récupérer un utilisateur depuis son token API."""
    if not token:
        return None
    
    if token.startswith('Bearer '):
        token = token[7:]
    
    return User.query.filter_by(api_key=token, is_active=True).first()

def generate_subdomain() -> str:
    """Générer un sous-domaine aléatoire unique."""
    import random
    import string
    
    while True:
        subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        if not Tunnel.query.filter_by(subdomain=subdomain).first():
            return subdomain

def validate_subdomain(subdomain: str) -> bool:
    """Valider un sous-domaine."""
    if not subdomain or len(subdomain) > 50:
        return False
    
    import re
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-_]*[a-zA-Z0-9]$', subdomain):
        return False
    
    return not Tunnel.query.filter_by(subdomain=subdomain.lower()).first()

def parse_duration(duration: str) -> timedelta:
    """Parser une durée en timedelta."""
    duration_map = {
        '1h': timedelta(hours=1),
        '2h': timedelta(hours=2),
        '4h': timedelta(hours=4),
        '8h': timedelta(hours=8),
        '12h': timedelta(hours=12),
        '24h': timedelta(hours=24)
    }
    return duration_map.get(duration, timedelta(hours=2))


# =============================================================================
# API Routes
# =============================================================================

@app.route('/api/health', methods=['GET'])
def health():
    """Point de santé du service."""
    
    # Determine database type from connection string
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if 'postgresql' in db_uri.lower():
        database_type = 'PostgreSQL'
    elif 'sqlite' in db_uri.lower():
        database_type = 'SQLite'
    else:
        database_type = 'Unknown'
    
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': datetime.utcnow().isoformat(),
        'active_tunnels': len(tunnel_service.active_tunnels),
        'database': database_type
    })


@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """Créer un nouveau compte."""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email et mot de passe requis'}), 400
    
    email = data['email'].lower().strip()
    password = data['password']
    
    # Validation email
    import re
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({'error': 'Email invalide'}), 400
    
    # Validation mot de passe
    if len(password) < 6:
        return jsonify({'error': 'Mot de passe trop court (minimum 6 caractères)'}), 400
    
    # Vérifier si l'utilisateur existe
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email déjà utilisé'}), 409
    
    try:
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'Compte créé avec succès',
            'user_id': user.id,
            'api_key': user.api_key
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Erreur lors de la création du compte'}), 500


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """Se connecter."""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email et mot de passe requis'}), 400
    
    user = User.query.filter_by(email=data['email'].lower().strip()).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Compte désactivé'}), 403
    
    # Mettre à jour la dernière connexion
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'message': 'Connexion réussie',
        'user_id': user.id,
        'api_key': user.api_key,
        'plan': user.plan
    })


@app.route('/api/auth/validate', methods=['GET'])
def validate_token():
    """Valider un token API."""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Token invalide'}), 401
    
    return jsonify({
        'valid': True,
        'user': user.to_dict()
    })


# 3. Modifier la fonction create_tunnel dans l'API
@app.route('/api/tunnels', methods=['POST'])
@limiter.limit("10 per minute")
def create_tunnel():
    """Créer un nouveau tunnel."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Données requises'}), 400
    
    # Récupérer l'utilisateur (optionnel pour mode gratuit)
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    # Validation des données
    port = data.get('port')
    if not port or not isinstance(port, int) or port < 1 or port > 65535:
        return jsonify({'error': 'Port invalide'}), 400
    
    # Ports bloqués
    blocked_ports = [22, 25, 53, 80, 443, 993, 995]
    if port in blocked_ports:
        return jsonify({'error': f'Port {port} bloqué pour des raisons de sécurité'}), 400
    
    # Sous-domaine
    subdomain = data.get('subdomain')
    if subdomain:
        if not validate_subdomain(subdomain):
            return jsonify({'error': 'Sous-domaine invalide ou déjà utilisé'}), 409
        subdomain = subdomain.lower()
    else:
        subdomain = generate_subdomain()
    
    # Durée
    duration_str = data.get('duration', '2h')
    duration = parse_duration(duration_str)
    
    # Limites pour utilisateurs non authentifiés
    if not user:
        # Limiter à 2h maximum pour les utilisateurs non authentifiés
        if duration > timedelta(hours=2):
            duration = timedelta(hours=2)
    
    # Construire l'URL publique
    base_domain = os.getenv('RAILWAY_STATIC_URL', '').replace('https://', '').replace('http://', '')
    if base_domain:
        public_url = f"https://{base_domain}/{subdomain}"
    else:
        public_url = f"http://localhost:8080/{subdomain}"
    
    try:
        tunnel = tunnel_service.create_tunnel(
            tunnel_id=secrets.token_urlsafe(8),
            user_id=user.id if user else None,
            subdomain=subdomain,
            port=port,
            public_url=public_url,
            expires_at=datetime.utcnow() + duration,
            cors_enabled=data.get('cors', False),
            https_enabled=data.get('https', False),
            webhook_mode=data.get('webhook', False)
        )
        
        # Définir un mot de passe si fourni
        if data.get('password'):
            tunnel.set_password(data['password'])
            db.session.commit()
        
        return jsonify(tunnel.to_dict()), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erreur lors de la création du tunnel: {str(e)}'}), 500


@app.route('/api/tunnels', methods=['GET'])
def list_tunnels():
    """Lister les tunnels d'un utilisateur."""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentification requise'}), 401
    
    tunnels = Tunnel.query.filter_by(
        user_id=user.id,
        status='active'
    ).filter(
        Tunnel.expires_at > datetime.utcnow()
    ).all()
    
    return jsonify({
        'tunnels': [tunnel.to_dict() for tunnel in tunnels]
    })


@app.route('/api/tunnels/<tunnel_id>', methods=['DELETE'])
def delete_tunnel_route(tunnel_id: str):
    """Supprimer un tunnel."""
    tunnel = tunnel_service.get_tunnel(tunnel_id)
    
    if not tunnel:
        return jsonify({'error': 'Tunnel non trouvé'}), 404
    
    # Vérifier les permissions
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if tunnel.user_id and (not user or user.id != tunnel.user_id):
        return jsonify({'error': 'Accès refusé'}), 403
    
    if tunnel_service.delete_tunnel(tunnel_id):
        return jsonify({'message': 'Tunnel supprimé'})
    
    return jsonify({'error': 'Erreur lors de la suppression'}), 500


@app.route('/api/tunnels/<tunnel_id>/stats', methods=['GET'])
def tunnel_stats(tunnel_id: str):
    """Récupérer les statistiques d'un tunnel."""
    tunnel = tunnel_service.get_tunnel(tunnel_id)
    
    if not tunnel:
        return jsonify({'error': 'Tunnel non trouvé'}), 404
    
    return jsonify(tunnel.to_dict())


# =============================================================================
# Proxy Routes
# =============================================================================

@app.route('/', methods=['GET'])
def index():
    """Page d'accueil."""
    html = """
    <!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FlaskTunnel - Tunnels HTTP Sécurisés</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #334155;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .header {
            text-align: center;
            margin-bottom: 4rem;
            color: white;
        }

        .logo {
            font-size: 3rem;
            margin-bottom: 1rem;
        }

        .title {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }

        .subtitle {
            font-size: 1.25rem;
            opacity: 0.9;
            max-width: 600px;
            margin: 0 auto;
        }

        .main-content {
            background: white;
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.1);
            overflow: hidden;
            backdrop-filter: blur(10px);
        }

        .stats-section {
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            padding: 2rem;
            border-bottom: 1px solid #e2e8f0;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            max-width: 800px;
            margin: 0 auto;
        }

        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }

        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: #2563eb;
            display: block;
        }

        .stat-label {
            color: #64748b;
            font-size: 0.875rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .content-section {
            padding: 3rem 2rem;
        }

        .section {
            margin-bottom: 3rem;
        }

        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .section-icon {
            font-size: 1.25rem;
        }

        .code-block {
            background: #1e293b;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
            position: relative;
            overflow-x: auto;
        }

        .code-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #334155;
        }

        .code-lang {
            color: #94a3b8;
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 1px;
        }

        .copy-btn {
            background: #3b82f6;
            color: white;
            border: none;
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: background 0.2s;
        }

        .copy-btn:hover {
            background: #2563eb;
        }

        .code-content {
            color: #e2e8f0;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 0.875rem;
            line-height: 1.5;
        }

        .highlight {
            color: #10b981;
            font-weight: 500;
        }

        .comment {
            color: #64748b;
            font-style: italic;
        }

        .keyword {
            color: #f59e0b;
        }

        .string {
            color: #06b6d4;
        }

        .api-list {
            display: grid;
            gap: 1rem;
        }

        .api-item {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            transition: all 0.2s ease;
        }

        .api-item:hover {
            background: #f1f5f9;
            border-color: #cbd5e1;
        }

        .api-method {
            background: #10b981;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            min-width: 60px;
            text-align: center;
        }

        .api-method.post {
            background: #3b82f6;
        }

        .api-method.get {
            background: #10b981;
        }

        .api-endpoint {
            font-family: monospace;
            font-weight: 500;
            color: #1e293b;
        }

        .api-description {
            color: #64748b;
            margin-left: auto;
        }

        .footer-links {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid #e2e8f0;
        }

        .footer-link {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: #3b82f6;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s;
        }

        .footer-link:hover {
            color: #2563eb;
        }

        .install-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: #10b981;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 500;
            margin-bottom: 1rem;
            transition: background 0.2s;
        }

        .install-badge:hover {
            background: #059669;
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }

            .title {
                font-size: 2rem;
            }

            .content-section {
                padding: 2rem 1rem;
            }

            .footer-links {
                flex-direction: column;
                gap: 1rem;
            }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.7;
            }
        }

        .status-online {
            color: #10b981;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo">🚀</div>
            <h1 class="title">FlaskTunnel</h1>
            <p class="subtitle">
                Exposez vos applications locales sur internet en quelques secondes avec des tunnels HTTP sécurisés
            </p>
        </header>

        <main class="main-content">
            <section class="stats-section">
                <div class="stats-grid">
                    <div class="stat-card">
                        <span class="stat-number">{{ active_tunnels }}</span>
                        <span class="stat-label">Tunnels Actifs</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">{{ total_users }}</span>
                        <span class="stat-label">Utilisateurs</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number status-online pulse">Online</span>
                        <span class="stat-label">Statut Serveur</span>
                    </div>
                </div>
            </section>

            <div class="content-section">
                <section class="section">
                    <h2 class="section-title">
                        <span class="section-icon">📦</span>
                        Installation
                    </h2>
                    <p>
                        Installez le client FlaskTunnel avec pip :
                    </p>
                    
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-lang">bash</span>
                            <button class="copy-btn" onclick="copyCode(this)">Copier</button>
                        </div>
                        <div class="code-content">
                            <span class="keyword">pip</span> <span class="string">install</span> flasktunnel-client
                        </div>
                    </div>
                </section>

                <section class="section">
                    <h2 class="section-title">
                        <span class="section-icon">⚡</span>
                        Utilisation Rapide
                    </h2>
                    
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-lang">bash</span>
                            <button class="copy-btn" onclick="copyCode(this)">Copier</button>
                        </div>
                        <div class="code-content">
                            <span class="comment"># Créer un tunnel vers le port 5000</span><br>
                            <span class="keyword">flasktunnel</span> --port <span class="highlight">5000</span><br><br>
                            
                            <span class="comment"># Avec sous-domaine personnalisé</span><br>
                            <span class="keyword">flasktunnel</span> --port <span class="highlight">3000</span> --subdomain <span class="string">monapp</span><br><br>
                            
                            <span class="comment"># Avec authentification</span><br>
                            <span class="keyword">flasktunnel</span> --port <span class="highlight">8000</span> --auth <span class="highlight">your-api-key</span><br><br>
                            
                            <span class="comment"># Avec protection par mot de passe</span><br>
                            <span class="keyword">flasktunnel</span> --port <span class="highlight">4000</span> --password <span class="string">secret123</span>
                        </div>
                    </div>
                </section>

                <section class="section">
                    <h2 class="section-title">
                        <span class="section-icon">🔌</span>
                        API Endpoints
                    </h2>
                    <div class="api-list">
                        <div class="api-item">
                            <span class="api-method post">POST</span>
                            <code class="api-endpoint">/api/auth/register</code>
                            <span class="api-description">Créer un nouveau compte</span>
                        </div>
                        <div class="api-item">
                            <span class="api-method post">POST</span>
                            <code class="api-endpoint">/api/auth/login</code>
                            <span class="api-description">Se connecter</span>
                        </div>
                        <div class="api-item">
                            <span class="api-method get">GET</span>
                            <code class="api-endpoint">/api/auth/validate</code>
                            <span class="api-description">Valider un token</span>
                        </div>
                        <div class="api-item">
                            <span class="api-method post">POST</span>
                            <code class="api-endpoint">/api/tunnels</code>
                            <span class="api-description">Créer un tunnel</span>
                        </div>
                        <div class="api-item">
                            <span class="api-method get">GET</span>
                            <code class="api-endpoint">/api/tunnels</code>
                            <span class="api-description">Lister les tunnels</span>
                        </div>
                        <div class="api-item">
                            <span class="api-method get">GET</span>
                            <code class="api-endpoint">/api/health</code>
                            <span class="api-description">Statut du serveur</span>
                        </div>
                    </div>
                </section>

                <section class="section">
                    <h2 class="section-title">
                        <span class="section-icon">🔧</span>
                        Exemple d'utilisation avec cURL
                    </h2>
                    
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-lang">bash</span>
                            <button class="copy-btn" onclick="copyCode(this)">Copier</button>
                        </div>
                        <div class="code-content">
                            <span class="comment"># Créer un tunnel</span><br>
                            <span class="keyword">curl</span> -X <span class="string">POST</span> {{ base_url }}/api/tunnels \<br>
                            &nbsp;&nbsp;-H <span class="string">"Content-Type: application/json"</span> \<br>
                            &nbsp;&nbsp;-d <span class="string">'{"port": 3000, "subdomain": "myapp"}'</span><br><br>
                            
                            <span class="comment"># Réponse</span><br>
                            {<br>
                            &nbsp;&nbsp;<span class="string">"tunnel_id"</span>: <span class="string">"abc123def"</span>,<br>
                            &nbsp;&nbsp;<span class="string">"public_url"</span>: <span class="highlight">"{{ base_url }}/myapp"</span>,<br>
                            &nbsp;&nbsp;<span class="string">"status"</span>: <span class="string">"active"</span><br>
                            }
                        </div>
                    </div>
                </section>

                <div class="footer-links">
                    <a href="https://docs.flasktunnel.dev" class="footer-link">
                        <span>📚</span>
                        Documentation
                    </a>
                    <a href="https://github.com/flasktunnel" class="footer-link">
                        <span>💻</span>
                        GitHub
                    </a>
                    <a href="https://status.flasktunnel.dev" class="footer-link">
                        <span>📊</span>
                        Status
                    </a>
                </div>
            </div>
        </main>
    </div>

    <script>
        function copyCode(button) {
            const codeBlock = button.closest('.code-block');
            const codeContent = codeBlock.querySelector('.code-content');
            const text = codeContent.innerText;
            
            navigator.clipboard.writeText(text).then(() => {
                const originalText = button.textContent;
                button.textContent = 'Copié !';
                button.style.background = '#10b981';
                
                setTimeout(() => {
                    button.textContent = originalText;
                    button.style.background = '#3b82f6';
                }, 2000);
            });
        }

        // Animation au scroll
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, observerOptions);

        // Appliquer l'animation à tous les éléments section
        document.querySelectorAll('.section').forEach(section => {
            section.style.opacity = '0';
            section.style.transform = 'translateY(20px)';
            section.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            observer.observe(section);
        });
    </script>
</body>
</html>
    """
    
    stats = {
        'active_tunnels': len(tunnel_service.active_tunnels),
        'total_users': User.query.count(),
        'base_url': base_domain if (base_domain := os.getenv('RAILWAY_STATIC_URL', '')) else 'http://localhost:8080'
    }
    
    return render_template_string(html, **stats)


# Dans votre route proxy_tunnel, remplacer par :
@app.route('/<subdomain>')
@app.route('/<subdomain>/<path:path>')
def proxy_tunnel(subdomain: str, path: str = ''):
    """Proxy via WebSocket vers le client local."""
    tunnel = Tunnel.query.filter_by(
        subdomain=subdomain,
        status='active'
    ).filter(
        Tunnel.expires_at > datetime.utcnow()
    ).first()
    
    if not tunnel:
        return jsonify({
            'error': 'Tunnel not found or expired',
            'subdomain': subdomain
        }), 404
    
    # Vérifier si le client est connecté via WebSocket
    tunnel_room = f"tunnel_{tunnel.tunnel_id}"
    connected_clients = socketio.manager.get_participants(tunnel_room)
    
    if not connected_clients:
        return jsonify({
            'error': 'Tunnel client not connected',
            'message': f'The tunnel client for {subdomain} is not connected. Please restart your FlaskTunnel client.',
            'tunnel': tunnel.to_dict()
        }), 502
    
    # Créer un ID unique pour cette requête
    import uuid
    request_id = str(uuid.uuid4())
    
    # Préparer les données de la requête
    request_data = {
        'request_id': request_id,
        'method': request.method,
        'path': f"/{path}",
        'headers': dict(request.headers),
        'params': dict(request.args),
        'body': request.get_data().decode('utf-8', errors='ignore') if request.get_data() else None
    }
    
    # Envoyer la requête via WebSocket et attendre la réponse
    response_data = None
    response_event = threading.Event()
    
    def handle_response(data):
        nonlocal response_data
        if data.get('request_id') == request_id:
            response_data = data
            response_event.set()
    
    # Écouter la réponse temporairement
    @socketio.on('tunnel_response')
    def on_tunnel_response(data):
        handle_response(data)
    
    # Envoyer la requête
    socketio.emit('tunnel_request', request_data, room=tunnel_room)
    
    # Attendre la réponse (timeout 30s)
    if response_event.wait(timeout=30):
        if 'error' in response_data:
            return jsonify({
                'error': 'Local service error',
                'message': response_data['error'],
                'tunnel': tunnel.to_dict()
            }), response_data.get('status_code', 502)
        
        # Construire la réponse HTTP
        content = response_data['content']
        if response_data.get('binary'):
            import base64
            content = base64.b64decode(content)
        
        # Mettre à jour les stats
        tunnel.requests_count += 1
        tunnel.last_activity = datetime.utcnow()
        tunnel.bytes_transferred += len(content) if isinstance(content, bytes) else len(content.encode())
        db.session.commit()
        
        # Headers (exclure certains headers)
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for name, value in response_data['headers'].items()
                  if name.lower() not in excluded_headers]
        
        # CORS si activé
        if tunnel.cors_enabled:
            headers.extend([
                ('Access-Control-Allow-Origin', '*'),
                ('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS'),
                ('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            ])
        
        return content, response_data['status_code'], headers
    
    else:
        return jsonify({
            'error': 'Request timeout',
            'message': 'The local service did not respond in time',
            'tunnel': tunnel.to_dict()
        }), 504


# =============================================================================
# WebSocket Events
# =============================================================================

@socketio.on('connect')
def handle_connect():
    """Client connecté."""
    print(f"Client connecté: {request.sid}")


@socketio.on('disconnect')
def handle_disconnect():
    """Client déconnecté."""
    print(f"Client déconnecté: {request.sid}")


@socketio.on('join_tunnel')
def handle_join_tunnel(data):
    """Le client rejoint la room de son tunnel."""
    tunnel_id = data.get('tunnel_id')
    if tunnel_id:
        join_room(f"tunnel_{tunnel_id}")
        emit('tunnel_joined', {'tunnel_id': tunnel_id})


@socketio.on('leave_tunnel')
def handle_leave_tunnel(data):
    """Quitter une room de tunnel."""
    tunnel_id = data.get('tunnel_id')
    if tunnel_id:
        leave_room(f"tunnel_{tunnel_id}")
        emit('tunnel_left', {'tunnel_id': tunnel_id})


# =============================================================================
# Error Handlers
# =============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'message': str(e.description)}), 429


# =============================================================================
# Cleanup on shutdown
# =============================================================================

import atexit

def cleanup():
    """Nettoyer les ressources au shutdown."""
    if tunnel_service:
        tunnel_service.stop_cleanup()

atexit.register(cleanup)


# =============================================================================
# Initialization corrigée pour Railway
# =============================================================================

def init_db():
    """Initialiser la base de données optimisée pour Railway."""
    try:
        with app.app_context():
            print("🔄 Initializing database...")
            
            # Afficher la configuration
            db_uri = app.config['SQLALCHEMY_DATABASE_URI']
            if 'postgresql' in db_uri:
                print("🐘 Using PostgreSQL (Railway)")
            else:
                print("🗄️  Using SQLite (Local)")
            
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    # Test de connexion
                    with db.engine.connect() as conn:
                        result = conn.execute(db.text("SELECT 1"))
                        result.fetchone()
                    
                    # Créer les tables
                    db.create_all()
                    print("✅ Database initialized successfully!")
                    tunnel_service.mark_db_initialized()
                    return True
                    
                except Exception as db_error:
                    print(f"❌ Database attempt {attempt + 1}/{max_retries} failed: {str(db_error)}")
                    
                    if attempt < max_retries - 1:
                        wait_time = min(2 ** attempt, 10)  # Backoff exponentiel
                        print(f"⏳ Retrying in {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        # Sur Railway, ne pas faire de fallback vers SQLite
                        if app.config.get('is_railway', False):
                            print("❌ Railway PostgreSQL connection failed - check DATABASE_URL")
                            raise db_error
                        else:
                            # Fallback SQLite uniquement en local
                            print("🔄 Falling back to SQLite...")
                            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flaskserver.db'
                            db.create_all()
                            print("✅ SQLite fallback initialized!")
                            tunnel_service.mark_db_initialized()
                            return True
                    
    except Exception as e:
        print(f"❌ Critical database error: {e}")
        return False


if __name__ == '__main__':
    # Mode développement local
    if not init_db():
        print("❌ Database initialization failed!")
        exit(1)
    
    port = int(os.getenv('PORT', 8080))
    debug = os.getenv('FLASK_ENV') != 'production'
    
    print(f"🚀 FlaskTunnel starting on port {port}")
    print(f"🔧 Debug mode: {debug}")
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        use_reloader=False,
        log_output=True
    )
else:
    # Mode production (Railway avec gunicorn)
    print("🚄 Running on Railway with gunicorn")
    
    def init_db_async():
        """Initialisation asynchrone pour éviter de bloquer gunicorn."""
        import threading
        def delayed_init():
            time.sleep(2)  # Laisser gunicorn démarrer
            try:
                success = init_db()
                if success:
                    print("✅ Railway database initialized")
                else:
                    print("❌ Railway database initialization failed")
            except Exception as e:
                print(f"❌ Railway DB error: {e}")
        
        thread = threading.Thread(target=delayed_init, daemon=True)
        thread.start()
    
    init_db_async()

# Cleanup handler
import atexit
def cleanup():
    if tunnel_service:
        tunnel_service.stop_cleanup()
atexit.register(cleanup)