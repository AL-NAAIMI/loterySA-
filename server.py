from flask import Flask, render_template, request, redirect, url_for, flash
import deploy
import json
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey_loterie_nailloux'

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

        user_address = request.form.get('address')
        user_key = request.form.get('key')
        
        if not user_address or not user_key:
            flash("Veuillez remplir tous les champs.", "error")
            return redirect(url_for('participer'))

        try:
            deploy.participer(contract_address, user_address, user_key)
            flash("Félicitations ! Vous avez participé avec succès.", "success")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"Erreur lors de la participation : {str(e)}", "error")
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

@app.route('/admin')
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
def admin_deploy():
    try:
        new_address = deploy.deploy_contract()
        flash(f"Nouveau contrat déployé à l'adresse : {new_address}", "success")
    except Exception as e:
        flash(f"Erreur de déploiement : {str(e)}", "error")
    
    return redirect(url_for('admin'))

@app.route('/admin/tirage', methods=['POST'])
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
    app.run(debug=True)
