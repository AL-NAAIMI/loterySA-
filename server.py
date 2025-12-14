from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
from markupsafe import escape
import deploy
import price_api
import json
import os
import secrets
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'itsMySecretKeyHOHOHO!')

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

# Credentials for admin login from environment variables
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' https://cdn.jsdelivr.net https://api.coingecko.com;"
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def validate_ethereum_address(address):
    """Validate Ethereum address format"""
    if not address or not isinstance(address, str):
        return False
    # Ethereum addresses are 42 characters (0x + 40 hex chars)
    pattern = r'^0x[a-fA-F0-9]{40}$'
    return bool(re.match(pattern, address))

def validate_private_key(key):
    """Validate private key format"""
    if not key or not isinstance(key, str):
        return False
    # Private keys are 66 characters (0x + 64 hex chars)
    pattern = r'^0x[a-fA-F0-9]{64}$'
    return bool(re.match(pattern, key))

def validate_pseudo(pseudo):
    """Validate pseudo format - only alphanumeric, spaces, hyphens, underscores"""
    if not pseudo or not isinstance(pseudo, str):
        return False
    # Length check
    if len(pseudo) < 2 or len(pseudo) > 30:
        return False
    # Only letters, numbers, spaces, hyphens, underscores
    pattern = r'^[a-zA-Z0-9 _-]+$'
    return bool(re.match(pattern, pseudo))

def sanitize_input(value, max_length=200):
    """Sanitize user input"""
    if not value:
        return ''
    return str(escape(value))[:max_length]

def get_active_contract():
    """Récupère l'adresse du contrat actif depuis state.json"""
    if os.path.exists("state.json"):
        try:
            with open("state.json", "r") as f:
                data = json.load(f)
                return data.get("contract_address")
        except:
            return None
    return None

def save_participant_pseudo(address, pseudo):
    """Sauvegarde le pseudo d'un participant"""
    if os.path.exists("state.json"):
        with open("state.json", "r") as f:
            data = json.load(f)
    else:
        data = {}
    
    if "participants" not in data:
        data["participants"] = {}
    
    data["participants"][address.lower()] = pseudo
    
    with open("state.json", "w") as f:
        json.dump(data, f)

def get_participant_pseudo(address):
    """Récupère le pseudo d'un participant"""
    if os.path.exists("state.json"):
        try:
            with open("state.json", "r") as f:
                data = json.load(f)
                participants = data.get("participants", {})
                return participants.get(address.lower(), None)
        except:
            return None
    return None

@app.route('/favicon.ico')
def favicon():
    """Serve favicon or return 204 No Content"""
    return '', 204

@app.route('/')
def index():
    contract_address = get_active_contract()
    eth_price_eur = price_api.get_eth_price_eur()
    ticket_price_eur = price_api.eth_to_eur(1)  # 1 ETH = prix du ticket
    return render_template('index.html', 
                         contract_address=contract_address,
                         eth_price_eur=eth_price_eur,
                         ticket_price_eur=ticket_price_eur)

@app.route('/participer', methods=['GET'])
def participer():
    """Page pour participer à la loterie via MetaMask"""
    contract_address = get_active_contract()
    eth_price_eur = price_api.get_eth_price_eur()
    ticket_price_eur = price_api.eth_to_eur(1)

    if not contract_address:
        contract_abi = []  # Aucun contrat actif
    else:
        abi, _ = deploy.get_contract_data()
        contract_abi = json.dumps(abi)

    return render_template(
        "participer.html",
        contract_address=contract_address,
        contract_abi=contract_abi,
        eth_price_eur=eth_price_eur,
        ticket_price_eur=ticket_price_eur
    )

@app.route('/save-pseudo', methods=['POST'])
def save_pseudo():
    """Sauvegarde le pseudo d'un participant (appelé par JavaScript)"""
    data = request.get_json()
    
    if not data:
        return {'success': False, 'message': 'Aucune donnée reçue'}, 400
    
    user_address = data.get('address', '').strip()
    user_pseudo = data.get('pseudo', '').strip()
    
    # Validate inputs
    if not user_address or not user_pseudo:
        return {'success': False, 'message': 'Adresse et pseudo requis'}, 400
    
    if not validate_ethereum_address(user_address):
        return {'success': False, 'message': 'Adresse Ethereum invalide'}, 400
    
    if not validate_pseudo(user_pseudo):
        return {'success': False, 'message': 'Pseudo invalide. Utilisez uniquement lettres, chiffres, espaces, tirets et underscores (2-30 caractères)'}, 400
    
    # Sanitize and save
    user_pseudo = sanitize_input(user_pseudo, max_length=30)
    save_participant_pseudo(user_address, user_pseudo)
    
    return {'success': True, 'message': f'Pseudo "{user_pseudo}" sauvegardé'}, 200

@app.route('/cagnotte')
def cagnotte():
    contract_address = get_active_contract()
    solde = 0
    eth_price_eur = price_api.get_eth_price_eur()
    solde_eur = 0
    winner_eur = 0
    owner_eur = 0
    error = None
    
    if contract_address:
        try:
            solde = float(deploy.get_balance(contract_address))
            solde_eur = price_api.eth_to_eur(solde)
            winner_eur = price_api.eth_to_eur(solde * 0.9)
            owner_eur = price_api.eth_to_eur(solde * 0.1)
        except Exception as e:
            error = "Erreur de lecture du solde"
            solde = 0
            
    return render_template('cagnotte.html', 
                         contract_address=contract_address, 
                         solde=solde,
                         eth_price_eur=eth_price_eur,
                         solde_eur=solde_eur,
                         winner_eur=winner_eur,
                         owner_eur=owner_eur,
                         error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '').strip(), max_length=50)
        password = request.form.get('password', '').strip()
        
        # Basic rate limiting check
        failed_attempts = session.get('failed_login_attempts', 0)
        if failed_attempts >= 5:
            flash('Trop de tentatives échouées. Veuillez réessayer dans quelques minutes.', 'error')
            return redirect(url_for('login'))
        
        if not username or not password:
            flash('Veuillez remplir tous les champs.', 'error')
            return redirect(url_for('login'))
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.clear()
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            flash('Connexion réussie ! Bienvenue.', 'success')
            return redirect(url_for('admin'))
        else:
            session['failed_login_attempts'] = failed_attempts + 1
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Vous avez été déconnecté avec succès.', 'success')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    contract_address = get_active_contract()
    solde = 0
    is_terminated = False
    winner_info = None
    eth_price_eur = price_api.get_eth_price_eur()
    
    if contract_address:
        try:
            solde = float(deploy.get_balance(contract_address))
            # Récupérer les infos du gagnant pour ce contrat spécifique
            winner_info = deploy.get_last_winner(contract_address)
            
            # Ajouter les conversions EUR si winner_info existe
            if winner_info and winner_info.get('prize'):
                winner_info['prize_eur'] = price_api.eth_to_eur(winner_info['prize'])
                winner_info['owner_fee_eur'] = price_api.eth_to_eur(winner_info['owner_fee'])
            
            # Le contrat est terminé seulement si le solde est 0 ET qu'il y a eu un gagnant
            if solde == 0 and winner_info and winner_info.get('winner'):
                is_terminated = True
        except:
            solde = 0
    
    solde_eur = price_api.eth_to_eur(solde)
    return render_template('admin.html', 
                         contract_address=contract_address, 
                         solde=solde, 
                         is_terminated=is_terminated, 
                         winner_info=winner_info,
                         eth_price_eur=eth_price_eur,
                         solde_eur=solde_eur)

@app.route('/admin/deploy', methods=['POST'])
@login_required
def admin_deploy():
    try:
        new_address = deploy.deploy_contract()
        flash(f"Nouveau contrat déployé à l'adresse : {new_address}", "success")
    except Exception as e:
        flash(f"Erreur de déploiement : {str(e)}", "error")
    
    return redirect(url_for('admin'))

@app.route('/admin/tirage', methods=['POST'])
@login_required
def admin_tirage():
    contract_address = get_active_contract()
    if not contract_address:
        flash("Aucun contrat actif pour le tirage.", "error")
        return redirect(url_for('admin'))
        
    try:
        deploy.tirage(contract_address)
        flash("Le tirage a été effectué avec succès ! La cagnotte a été transférée au gagnant.", "success")
    except Exception as e:
        error_message = str(e)
        # Check for specific error messages
        if "Il faut plus de participants" in error_message or "participants" in error_message.lower():
            flash("❌ Impossible de lancer le tirage : Il faut au moins 3 participants pour effectuer le tirage.", "error")
        elif "Seul le proprietaire" in error_message or "owner" in error_message.lower():
            flash("❌ Erreur : Seul le propriétaire peut lancer le tirage.", "error")
        else:
            flash(f"❌ Erreur lors du tirage : {error_message}", "error")
        
    return redirect(url_for('admin'))

if __name__ == '__main__':
    # Set debug=False in production
    app.run(debug=os.environ.get('FLASK_DEBUG', 'True') == 'True', host='127.0.0.1')
