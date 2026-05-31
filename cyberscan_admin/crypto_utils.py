"""
CyberScan - Module de chiffrement pour sécurisation des données sensibles
Utilise AES-256-GCM pour le chiffrement des clés API et données confidentielles
"""

import os
import base64
import hashlib
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _get_machine_key():
    """
    Génère une clé unique basée sur les caractéristiques de la machine.
    Cette clé ne change pas tant que la machine reste la même.
    """
    try:
        import platform
        import socket
        import uuid
        
        # Combinaison d'identifiants machine stables
        components = [
            platform.node(),  # Nom machine
            platform.machine(),  # Architecture
            str(uuid.getnode()),  # MAC address
            socket.gethostname(),
        ]
        
        # Hash unique machine
        machine_string = "|".join(components)
        key = hashlib.sha256(machine_string.encode()).digest()
        return key
    except Exception as e:
        logging.error(f"Erreur génération clé machine: {e}")
        # Fallback: clé dérivée du chemin d'installation
        fallback = hashlib.sha256(os.path.abspath(__file__).encode()).digest()
        return fallback

def encrypt_data(plaintext: str) -> str:
    """
    Chiffre une chaîne de caractères avec AES-256-GCM.
    Retourne une chaîne base64 contenant: salt + nonce + ciphertext + tag
    """
    try:
        if not plaintext:
            return ""
            
        # Générer un salt aléatoire
        salt = os.urandom(16)
        
        # Dériver la clé AES depuis la clé machine + salt (hashlib natif)
        key = hashlib.pbkdf2_hmac('sha256', _get_machine_key(), salt, 100000, dklen=32)
        
        # Générer un nonce aléatoire
        nonce = os.urandom(12)
        
        # Chiffrer
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        
        # Format: salt(16) + nonce(12) + ciphertext(var)
        encrypted = salt + nonce + ciphertext
        return base64.b64encode(encrypted).decode('utf-8')
        
    except Exception as e:
        logging.error(f"Erreur chiffrement: {e}")
        return ""

def decrypt_data(encrypted_b64: str) -> str:
    """
    Déchiffre une chaîne chiffrée avec AES-256-GCM.
    """
    try:
        if not encrypted_b64:
            return ""
            
        # Décoder base64
        encrypted = base64.b64decode(encrypted_b64.encode('utf-8'))
        
        # Extraire les composants
        salt = encrypted[:16]
        nonce = encrypted[16:28]
        ciphertext = encrypted[28:]
        
        # Re-dériver la clé (hashlib natif)
        key = hashlib.pbkdf2_hmac('sha256', _get_machine_key(), salt, 100000, dklen=32)
        
        # Déchiffrer
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
        
    except Exception as e:
        logging.error(f"Erreur déchiffrement (clé corrompue ou modifiée?): {e}")
        return ""

# Test unitaire
if __name__ == "__main__":
    test_data = "sk-test-api-key-12345"
    encrypted = encrypt_data(test_data)
    print(f"Original: {test_data}")
    print(f"Chiffré: {encrypted[:50]}...")
    decrypted = decrypt_data(encrypted)
    print(f"Déchiffré: {decrypted}")
    print(f"✅ Test réussi: {test_data == decrypted}")
