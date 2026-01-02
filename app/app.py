from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# --- VULNÉRABILITÉ 1 : Secret codé en dur (CWE-798) ---
# 
API_KEY_EXTERNE = "sk-12345ABCDE67890FGHIJKL" 

def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE users (id INTEGER, username TEXT, role TEXT)')
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'super-admin')")
    cursor.execute("INSERT INTO users VALUES (2, 'alice', 'user')")
    return conn

db_conn = init_db()

@app.route('/')
def index():
    return "<h1>Bienvenue sur l'application vulnérable !</h1><p>Utilisez /user?name=alice</p>"

@app.route('/user')
def get_user():
    username = request.args.get('name')
    
    # --- VULNÉRABILITÉ 2 : Injection SQL (CWE-89) ---
    # 
    # Mauvaise pratique : On concatène directement l'entrée utilisateur dans la requête
    query = f"SELECT role FROM users WHERE username = '{username}'"
    
    cursor = db_conn.cursor()
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        if result:
            return f"L'utilisateur {username} a le rôle : {result[0]}"
        else:
            return "Utilisateur non trouvé.", 404
    except Exception as e:
        return f"Erreur base de données : {str(e)}", 500

if __name__ == '__main__':
    # On lance l'app en mode debug (pas recommandé en prod)
    app.run(host='0.0.0.0', port=5000)
