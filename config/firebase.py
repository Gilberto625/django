# config/firebase.py
import firebase_admin
from firebase_admin import credentials
import os

# Usar la ruta correcta del archivo de credenciales
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cred_path = os.path.join(base_dir, 'config', 'firebase-service-account.json')

cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred)