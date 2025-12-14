import requests
from datetime import datetime, timedelta

# Cache pour éviter trop de requêtes API
_price_cache = {
    'price': None,
    'timestamp': None
}

def get_eth_price_eur():
    """Récupère le prix de l'ETH en EUR depuis CoinGecko API"""
    
    # Vérifier le cache (valide pendant 60 secondes)
    if _price_cache['price'] and _price_cache['timestamp']:
        if datetime.now() - _price_cache['timestamp'] < timedelta(seconds=60):
            return _price_cache['price']
    
    try:
        # API CoinGecko gratuite
        url = "https://api.coingecko.com/api/v3/simple/price"
        params = {
            'ids': 'ethereum',
            'vs_currencies': 'eur'
        }
        
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        
        data = response.json()
        price = data['ethereum']['eur']
        
        # Mettre à jour le cache
        _price_cache['price'] = price
        _price_cache['timestamp'] = datetime.now()
        
        return price
    
    except Exception as e:
        print(f"Erreur lors de la récupération du prix ETH: {e}")
        # Retourner un prix par défaut en cas d'erreur
        return 2000.0  # Prix approximatif

def eth_to_eur(eth_amount):
    """Convertit un montant en ETH vers EUR"""
    if eth_amount == 0:
        return 0.0
    
    price = get_eth_price_eur()
    return eth_amount * price

def format_currency(amount):
    """Formate un montant en EUR avec séparateurs"""
    return f"{amount:,.2f}".replace(',', ' ')
