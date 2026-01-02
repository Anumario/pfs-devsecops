# Utilisation d'une image de base Python
FROM python:3.9-slim

# Définition du dossier de travail
WORKDIR /app

# Copie des fichiers de dépendances
COPY requirements.txt .

# Installation des dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code source
COPY . .

# --- VULNÉRABILITÉ 3 : Configuration non sécurisée (User root) ---
# 
# Nous ne définissons pas d'utilisateur spécifique (USER), 
# donc Docker utilise 'root' par défaut. C'est dangereux.

# Port exposé
EXPOSE 5000

# Commande de lancement
CMD ["python", "app.py"]
