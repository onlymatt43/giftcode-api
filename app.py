from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify
import hashlib, uuid, json, os, hmac, time
from datetime import datetime, timedelta

# Cache en mémoire pour optimiser les performances
class CodeCache:
    def __init__(self):
        self.active_codes = {}  # user_code -> données complètes
        self.last_cleanup = time.time()
    
    def get_active_code(self, user_code):
        """Récupère un code du cache s'il est encore valide"""
        if user_code.upper() not in self.active_codes:
            return None
        
        code_data = self.active_codes[user_code.upper()]
        
        # Vérifier si le code est expiré
        if code_data.get('start_time'):
            start_time = datetime.fromisoformat(code_data['start_time'])
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            if elapsed >= code_data['duration'] * 60:
                # Code expiré, le supprimer du cache
                self.remove_code(user_code)
                return None
        
        return code_data
    
    def set_active_code(self, user_code, code_data):
        """Met en cache un code actif"""
        self.active_codes[user_code.upper()] = code_data
        
        # Nettoyage périodique (toutes les 5 minutes)
        if time.time() - self.last_cleanup > 300:
            self.cleanup_expired()
    
    def remove_code(self, user_code):
        """Supprime un code du cache"""
        self.active_codes.pop(user_code.upper(), None)
    
    def cleanup_expired(self):
        """Nettoie les codes expirés du cache"""
        now = datetime.utcnow()
        expired_codes = []
        
        for user_code, code_data in self.active_codes.items():
            if code_data.get('start_time'):
                start_time = datetime.fromisoformat(code_data['start_time'])
                elapsed = (now - start_time).total_seconds()
                if elapsed >= code_data['duration'] * 60:
                    expired_codes.append(user_code)
        
        for code in expired_codes:
            self.remove_code(code)
        
        self.last_cleanup = time.time()
        if expired_codes:
            print(f"Cache cleanup: {len(expired_codes)} codes expirés supprimés")

# Instance globale du cache
code_cache = CodeCache()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your_secret_key_change_in_production")

# Configuration optimisée pour la production
app.config.update(
    PERMANENT_SESSION_LIFETIME=3600,  # 1 heure
    SESSION_COOKIE_SECURE=True if os.getenv("RENDER") else False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SEND_FILE_MAX_AGE_DEFAULT=31536000,  # Cache statique 1 an
    TEMPLATES_AUTO_RELOAD=False if os.getenv("RENDER") else True,
    JSON_SORT_KEYS=False,  # Plus rapide
)

@app.after_request
def add_performance_headers(response):
    """Ajoute les headers de performance"""
    # Headers de sécurité et performance
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Cache intelligent selon le type de contenu
    if response.content_type:
        if 'text/css' in response.content_type or 'javascript' in response.content_type:
            # Cache long pour les assets statiques
            response.cache_control.max_age = 31536000  # 1 an
            response.cache_control.public = True
        elif 'text/html' in response.content_type:
            # Cache court pour HTML
            response.cache_control.max_age = 300  # 5 minutes
            response.cache_control.must_revalidate = True
        elif 'application/json' in response.content_type:
            # Pas de cache pour les API
            response.cache_control.no_cache = True
    
    return response

# Configuration des URLs
PRODUCTION_URL = "https://giftcode-api.onrender.com"
LOCAL_URL = "http://localhost:5000"

def get_base_url():
    """Retourne l'URL de base selon l'environnement"""
    # En production Render, utiliser l'URL configurée
    if os.getenv("RENDER") or "giftcode-api.onrender.com" in request.host or "onrender.com" in request.host:
        return PRODUCTION_URL
    # En local ou autre environnement
    return request.url_root.rstrip('/')

# Configuration des répertoires
DATA_DIR = 'data'
IFRAME_FILE = os.path.join(DATA_DIR, 'iframe_data.json')
CODES_FILE = os.path.join(DATA_DIR, 'access_codes.json')
LOG_FILE = os.path.join(DATA_DIR, 'logs.json')

# Variables globales pour le stockage
iframe_data = []
access_codes = {}

def load_data():
    """Charge les données depuis les fichiers JSON"""
    global iframe_data, access_codes
    os.makedirs(DATA_DIR, exist_ok=True)
    
    try:
        if os.path.exists(IFRAME_FILE):
            with open(IFRAME_FILE, 'r') as f:
                iframe_data = json.load(f)
        else:
            iframe_data = []
    except:
        iframe_data = []
    
    try:
        if os.path.exists(CODES_FILE):
            with open(CODES_FILE, 'r') as f:
                access_codes = json.load(f)
        else:
            access_codes = {}
    except:
        access_codes = {}
    
    # Migration : Corriger les anciennes URLs
    migrate_old_urls()

def migrate_old_urls():
    """Migre les anciennes URLs vers la bonne URL de production"""
    global iframe_data
    updated = False
    
    for item in iframe_data:
        # Corriger les URLs avec l'ancien domaine
        if 'iframe_url' in item and 'only-access.onrender.com' in item['iframe_url']:
            old_url = item['iframe_url']
            item['iframe_url'] = old_url.replace('only-access.onrender.com', 'giftcode-api.onrender.com')
            updated = True
            print(f"Migrated URL: {old_url} -> {item['iframe_url']}")
        
        if 'base_domain' in item and 'only-access.onrender.com' in item['base_domain']:
            item['base_domain'] = item['base_domain'].replace('only-access.onrender.com', 'giftcode-api.onrender.com')
            updated = True
    
    if updated:
        save_data()
        print("Migration des URLs terminée!")

def save_data():
    """Sauvegarde les données dans les fichiers JSON"""
    os.makedirs(DATA_DIR, exist_ok=True)
    
    with open(IFRAME_FILE, 'w') as f:
        json.dump(iframe_data, f, indent=2)
    
    with open(CODES_FILE, 'w') as f:
        json.dump(access_codes, f, indent=2)

def log_code_use(code, ip, title, start_time, expires_in):
    """Enregistre l'utilisation d'un code dans les logs"""
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
    except:
        logs = []
    
    logs.append({
        'code': code,
        'ip': ip,
        'title': title,
        'start_time': start_time.isoformat(),
        'expires_in': expires_in,
        'timestamp': datetime.utcnow().isoformat()
    })
    
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=2)

def get_client_ip():
    """Récupère l'IP du client"""
    return request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')

def generate_hash(data):
    """Génère un hash SHA256"""
    return hashlib.sha256(str(data).encode()).hexdigest()

def generate_code():
    """Génère un code d'accès unique (hash technique invisible)"""
    return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:12].upper()

def generate_user_code(subtitle, parent_token, index=0):
    """Génère un code utilisateur basé sur le sous-titre"""
    # Nettoyer le sous-titre (enlever espaces, caractères spéciaux)
    clean_subtitle = ''.join(c.upper() for c in subtitle if c.isalnum())
    
    # Tronquer si trop long
    if len(clean_subtitle) > 8:
        clean_subtitle = clean_subtitle[:8]
    elif len(clean_subtitle) < 4:
        clean_subtitle = clean_subtitle.ljust(4, 'X')
    
    # Ajouter un suffixe unique basé sur l'index et une partie du parent_token
    suffix = f"{index+1:02d}" + parent_token[-2:]  # 2 chiffres + 2 derniers chars du token
    
    return f"{clean_subtitle}-{suffix}"

def generate_parent_token():
    """Génère un token parent unique pour une famille"""
    return "FAM-" + hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:16].upper()

def find_code_optimized(user_code):
    """Recherche optimisée d'un code avec cache"""
    if not user_code:
        return None, None
    
    # 1. Vérifier d'abord le cache (très rapide)
    cached_data = code_cache.get_active_code(user_code)
    if cached_data:
        # Trouver la clé technique correspondante
        for hash_key, data in access_codes.items():
            if data.get('user_code', '').upper() == user_code.upper():
                return data, hash_key
    
    # 2. Recherche dans les données complètes (plus lente)
    for hash_key, data in access_codes.items():
        if data.get('user_code', '').upper() == user_code.upper():
            # Mettre en cache si le code est actif
            if data.get('status') == 'active':
                code_cache.set_active_code(user_code, data)
            return data, hash_key
    
    return None, None

def validate_family_separation(title, parent_token):
    """Vérifie que le title et parent_token sont cohérents et uniques"""
    # Vérifier qu'aucune autre famille n'utilise ce title
    for item in iframe_data:
        if item['title'] == title and item['parent_token'] != parent_token:
            return False, f"Le title '{title}' est déjà utilisé par une autre famille"
    
    # Vérifier que le parent_token est unique
    for item in iframe_data:
        if item['parent_token'] == parent_token and item['title'] != title:
            return False, f"Token parent '{parent_token}' déjà utilisé"
    
    return True, None

# Initialisation des données
load_data()

@app.route('/', methods=['GET', 'POST'])
def admin_login():
    """Page de connexion admin"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == 'adminonly' and password == 'a1d2m3i4n5':
            session['admin'] = True
            return redirect(url_for('admin_panel'))
        else:
            return render_template('admin.html', error="Identifiants incorrects")
    
    # Si déjà connecté, rediriger vers le panel
    if session.get('admin'):
        return redirect(url_for('admin_panel'))
    
    return render_template('admin.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    """Panel d'administration"""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    generated_codes = []
    
    if request.method == 'POST':
        # Formulaire 1: Création d'un nouveau title avec URL de provenance
        if 'create_title' in request.form:
            title = request.form.get('title', '').strip()
            source_url = request.form.get('source_url', '').strip()
            merchant_link = request.form.get('merchant_link', '').strip()
            
            if title and source_url:
                # Vérifier si le title existe déjà
                existing = next((item for item in iframe_data if item['title'] == title), None)
                if not existing:
                    # Générer un token parent unique pour cette famille
                    parent_token = generate_parent_token()
                    
                    # Validation de la séparation des familles
                    is_valid, error_msg = validate_family_separation(title, parent_token)
                    if not is_valid:
                        return render_template('admin.html', 
                                             iframe_data=iframe_data, 
                                             access_codes=access_codes, 
                                             generated_codes=[],
                                             admin_mode=True,
                                             error=error_msg)
                    
                    # Générer automatiquement l'URL de l'iframe (générique, sans titre)
                    base_url = get_base_url()
                    iframe_url = f"{base_url}/unlock"
                    
                    iframe_data.append({
                        'title': title,
                        'parent_token': parent_token,     # Token unique de la famille
                        'source_url': source_url,         # URL du site à protéger
                        'iframe_url': iframe_url,         # URL de notre page unlock (production)
                        'merchant_link': merchant_link if merchant_link else None,  # Optionnel
                        'base_domain': base_url,          # Domaine de base utilisé
                        'created': datetime.utcnow().isoformat()
                    })
                    save_data()
                    
                    # Message de succès avec informations complètes
                    success_msg = f"""✅ Famille '{title}' créée avec succès !
                    
🔗 URL du MUR NUMÉRIQUE : {iframe_url}

🧱 COMMENT FONCTIONNE HIT-THE-WALL :
1️⃣ Intégrez ce mur numérique sur votre site (zone à protéger)
2️⃣ Vos visiteurs "frappent le mur" et doivent saisir leur CARTE BLANCHE
3️⃣ Après validation du code → Le mur s'effondre et révèle : {source_url}
4️⃣ Générez des codes CARTE BLANCHE dans la section 2

💡 Code iframe pour créer votre HIT-THE-WALL :
<iframe src="{iframe_url}" width="100%" height="600px" frameborder="0"></iframe>

🎯 Titre "{title}" = Nom de famille pour organiser vos différents murs"""

                    return render_template('admin.html', 
                                         iframe_data=iframe_data, 
                                         access_codes=access_codes, 
                                         generated_codes=[],
                                         admin_mode=True,
                                         success=success_msg)
        
        # Formulaire 2: Génération de codes pour un title existant
        elif 'generate_codes' in request.form:
            selected_title = request.form.get('selected_title')
            subtitle = request.form.get('subtitle', '').strip()
            duration = int(request.form.get('duration', 20))
            count = int(request.form.get('count', 1))
            
            if selected_title and subtitle:
                # Récupérer le parent_token de la famille sélectionnée
                family_info = next((item for item in iframe_data if item['title'] == selected_title), None)
                if not family_info:
                    return render_template('admin.html', 
                                         iframe_data=iframe_data, 
                                         access_codes=access_codes, 
                                         generated_codes=[],
                                         admin_mode=True,
                                         error=f"Famille '{selected_title}' non trouvée")
                
                parent_token = family_info['parent_token']
                
                for i in range(count):
                    # Générer le hash technique (invisible)
                    technical_hash = generate_code()
                    
                    # Générer le code utilisateur basé sur le sous-titre
                    user_code = generate_user_code(subtitle, parent_token, i)
                    
                    # Vérifier que le code utilisateur n'existe pas déjà
                    existing_codes = [data.get('user_code') for data in access_codes.values()]
                    counter = 1
                    original_user_code = user_code
                    while user_code in existing_codes:
                        user_code = f"{original_user_code}#{counter}"
                        counter += 1
                    
                    access_codes[technical_hash] = {
                        'title': selected_title,
                        'parent_token': parent_token,      # Lien avec le token parent
                        'subtitle': subtitle,
                        'user_code': user_code,            # Code visible pour l'utilisateur
                        'technical_hash': technical_hash,   # Hash technique (clé du dictionnaire)
                        'duration': duration,              # en minutes
                        'used_by': None,
                        'start_time': None,
                        'created': datetime.utcnow().isoformat(),
                        'status': 'unused'
                    }
                    generated_codes.append({
                        'user_code': user_code,
                        'technical_hash': technical_hash,
                        'subtitle': subtitle
                    })
                save_data()
    
    return render_template('admin.html', 
                         iframe_data=iframe_data, 
                         access_codes=access_codes, 
                         generated_codes=generated_codes,
                         admin_mode=True)

@app.route('/delete-title', methods=['POST'])
def delete_title():
    """Supprime un title et tous ses codes associés"""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    title_to_delete = request.form.get('title_to_delete')
    
    if title_to_delete:
        # Supprimer le title des iframe_data et tous ses codes enfants
        global iframe_data, access_codes
        family_to_delete = next((item for item in iframe_data if item['title'] == title_to_delete), None)
        
        if family_to_delete:
            parent_token = family_to_delete.get('parent_token')
            
            # Supprimer la famille
            iframe_data = [item for item in iframe_data if item['title'] != title_to_delete]
            
            # Supprimer tous les codes de cette famille (par title ET parent_token pour sécurité)
            access_codes = {k: v for k, v in access_codes.items() 
                          if not (v['title'] == title_to_delete and v.get('parent_token') == parent_token)}
            
            save_data()
    
    return redirect(url_for('admin_panel'))

@app.route('/unlock', methods=['GET', 'POST'])
@app.route('/unlock/<title>', methods=['GET', 'POST'])
def unlock(title=None):
    """Page de déblocage avec gestion des codes d'accès"""
    user_ip = get_client_ip()
    code_input = None
    code_valid = False
    iframe_url = None
    merchant_link = None
    remaining_time = None
    expired = False
    error_msg = None
    title_info = None
    
    # Détection de bot (champ caché email)
    if request.method == 'POST' and request.form.get('email'):
        return "Bot detected", 403
    
    # Récupération du code (depuis POST ou cookie)
    if request.method == 'POST':
        code_input = request.form.get('access_code', '').strip().upper()
    else:
        code_input = request.cookies.get('access_code')
    
    # Si un title est spécifié dans l'URL, récupérer ses infos
    if title:
        title_info = next((item for item in iframe_data if item['title'] == title), None)
        if title_info:
            iframe_url = title_info['source_url']  # Utiliser l'URL du site à protéger
            merchant_link = title_info['merchant_link']
    
    # Traitement du code d'accès avec optimisations
    if code_input:
        # Recherche optimisée avec cache
        code_data, technical_hash = find_code_optimized(code_input)
        
        if code_data:
            # Vérification stricte de la famille : title ET parent_token doivent correspondre
            if title:
                family_info = next((item for item in iframe_data if item['title'] == title), None)
                if not family_info:
                    error_msg = "Famille non trouvée."
                elif code_data['title'] != title or code_data.get('parent_token') != family_info.get('parent_token'):
                    error_msg = f"Ce code '{code_input}' n'appartient pas à la famille '{title}'. Séparation des familles strictement appliquée."
            
            # Si le code n'a jamais été utilisé
            elif not code_data['used_by']:
                code_data['used_by'] = user_ip
                code_data['start_time'] = datetime.utcnow().isoformat()
                code_data['status'] = 'active'
                
                # Mettre en cache le code actif
                code_cache.set_active_code(code_input, code_data)
                
                # Log de l'utilisation (avec le code utilisateur visible)
                log_code_use(code_input, user_ip, code_data['title'], 
                            datetime.utcnow(), code_data['duration'])
                
                code_valid = True
                remaining_time = code_data['duration'] * 60  # en secondes
                
                # Récupérer les infos du title si pas déjà fait
                if not title_info:
                    title_info = next((item for item in iframe_data if item['title'] == code_data['title']), None)
                    if title_info:
                        iframe_url = title_info['source_url']  # Utiliser l'URL du site à protéger
                        merchant_link = title_info['merchant_link']
                
                save_data()
            
            # Si le code est utilisé par une autre IP
            elif code_data['used_by'] != user_ip:
                error_msg = f"Le code '{code_input}' est déjà utilisé par une autre adresse IP."
            
            # Si le code est utilisé par la même IP, vérifier le temps
            else:
                start_time = datetime.fromisoformat(code_data['start_time'])
                elapsed_seconds = (datetime.utcnow() - start_time).total_seconds()
                total_duration_seconds = code_data['duration'] * 60
                
                if elapsed_seconds < total_duration_seconds:
                    # Code encore valide
                    code_valid = True
                    remaining_time = int(total_duration_seconds - elapsed_seconds)
                    
                    # Récupérer les infos du title
                    title_info = next((item for item in iframe_data if item['title'] == code_data['title']), None)
                    if title_info:
                        iframe_url = title_info['source_url']  # Utiliser l'URL du site à protéger
                        merchant_link = title_info['merchant_link']
                else:
                    # Code expiré
                    expired = True
                    code_data['status'] = 'expired'
                    code_cache.remove_code(code_input)  # Supprimer du cache
                    save_data()
        
        else:
            error_msg = f"Code d'accès '{code_input}' invalide."
    
    # Créer la réponse avec template optimisé
    response = make_response(render_template('unlock_fast.html',
                                           code_valid=code_valid,
                                           iframe_url=iframe_url,
                                           merchant_link=merchant_link,
                                           remaining_time=remaining_time,
                                           expired=expired,
                                           error_msg=error_msg,
                                           title=title))
    
    # Définir le cookie si le code est valide et vient d'être soumis
    if code_valid and request.method == 'POST' and code_input:
        response.set_cookie('access_code', code_input, max_age=86400)  # Sauvegarder le user_code
    
    return response

@app.route('/logout')
def logout():
    """Déconnexion admin"""
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/info/<title>')
def title_info(title):
    """Affiche les informations d'intégration pour un title"""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    title_info = next((item for item in iframe_data if item['title'] == title), None)
    if not title_info:
        return "Title non trouvé", 404
    
    return render_template('title_info.html', title_info=title_info)

@app.route('/api/check-time', methods=['POST'])
def check_time():
    """API optimisée pour vérifier le temps restant via AJAX"""
    user_code = request.cookies.get('access_code')
    if not user_code:
        return jsonify({'valid': False, 'remaining': 0})
    
    # Recherche optimisée avec cache
    code_data, _ = find_code_optimized(user_code)
    
    if not code_data:
        return jsonify({'valid': False, 'remaining': 0})
    
    user_ip = get_client_ip()
    
    if code_data['used_by'] != user_ip:
        return jsonify({'valid': False, 'remaining': 0})
    
    start_time = datetime.fromisoformat(code_data['start_time'])
    elapsed_seconds = (datetime.utcnow() - start_time).total_seconds()
    total_duration_seconds = code_data['duration'] * 60
    
    if elapsed_seconds < total_duration_seconds:
        remaining = int(total_duration_seconds - elapsed_seconds)
        return jsonify({'valid': True, 'remaining': remaining})
    else:
        code_data['status'] = 'expired'
        code_cache.remove_code(user_code)  # Supprimer du cache
        save_data()
        return jsonify({'valid': False, 'remaining': 0})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)