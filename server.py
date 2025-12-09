from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
from markupsafe import escape
import deploy
import json
import os
import secrets
import re

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'itsMySecretKeyHOHOHO!')

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

# Credentials for admin login ill change it later to env variables
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'nailloux2025')

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
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

@app.route('/')
def index():
    contract_address = get_active_contract()
    return render_template('index.html', contract_address=contract_address)

@app.route('/participer', methods=['GET', 'POST'])
def participer():
    contract_address = get_active_contract()
    
    if request.method == 'POST':
        if not contract_address:
            flash("Erreur : Aucun contrat n'est actif actuellement.", "error")
            return redirect(url_for('index'))

        user_address = request.form.get('address', '').strip()
        user_key = request.form.get('key', '').strip()
        
        # Validate inputs
        if not user_address or not user_key:
            flash("Veuillez remplir tous les champs.", "error")
            return redirect(url_for('participer'))
        
        if not validate_ethereum_address(user_address):
            flash("Adresse Ethereum invalide. Format attendu : 0x suivi de 40 caractères hexadécimaux.", "error")
            return redirect(url_for('participer'))
        
        if not validate_private_key(user_key):
            flash("Clé privée invalide. Format attendu : 0x suivi de 64 caractères hexadécimaux.", "error")
            return redirect(url_for('participer'))

        try:
            deploy.participer(contract_address, user_address, user_key)
            flash("Félicitations ! Vous avez participé avec succès.", "success")
            return redirect(url_for('index'))
        except Exception as e:
            # Don't expose internal errors to users
            flash("Erreur lors de la participation. Veuillez vérifier vos informations.", "error")
            app.logger.error(f"Participation error: {str(e)}")
            return redirect(url_for('participer'))

    return render_template('participer.html', contract_address=contract_address)

@app.route('/cagnotte')
def cagnotte():
    contract_address = get_active_contract()
    solde = 0
    if contract_address:
        try:
            solde = deploy.get_balance(contract_address)
        except:
            solde = "Erreur de lecture"
            
    return render_template('cagnotte.html', contract_address=contract_address, solde=solde)

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
    if contract_address:
        try:
            solde = deploy.get_balance(contract_address)
        except:
            solde = 0
    return render_template('admin.html', contract_address=contract_address, solde=solde)

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
        flash(f"Erreur lors du tirage : {str(e)}", "error")
        
    return redirect(url_for('admin'))

if __name__ == '__main__':
    # Set debug=False in production
    app.run(debug=os.environ.get('FLASK_DEBUG', 'True') == 'True', host='127.0.0.1')
