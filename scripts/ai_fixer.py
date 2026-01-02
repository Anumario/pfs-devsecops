import json
import requests
import os
import subprocess
from git import Repo

# --- CONFIGURATION ---
OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3"
REPORT_PATH = "scan-report.json"
REPO_PATH = os.getcwd()  # Dossier actuel (racine du projet)

def get_ai_correction(vulnerability_detail, current_code):
    """Demande à Llama 3 de corriger le code source."""
    prompt = f"""
    Tu es un ingénieur expert en sécurité DevSecOps.
    Une faille a été détectée : {vulnerability_detail}
    
    Voici le code source actuel :
    ---
    {current_code}
    ---
    
    TACHE :
    Réécris le code COMPLET du fichier en corrigeant cette faille.
    Utilise les meilleures pratiques de sécurité (ex: requêtes paramétrées).
    RETOURNE UNIQUEMENT LE CODE, SANS AUCUNE EXPLICATION.
    """
    
    payload = {"model": MODEL_NAME, "prompt": prompt, "stream": False}
    try:
        response = requests.post(OLLAMA_API_URL, json=payload)
        return response.json().get('response', '').strip()
    except Exception as e:
        print(f"Erreur Ollama : {e}")
        return None

def apply_fix_and_push(file_path, new_content, vuln_id):
    """Crée une branche, applique le code et push sur GitHub."""
    repo = Repo(REPO_PATH)
    branch_name = f"fix/ai-remediation-{vuln_id.lower()}"
    
    # 1. Créer et basculer sur une nouvelle branche
    print(f"--- Création de la branche : {branch_name}")
    new_branch = repo.create_head(branch_name)
    new_branch.checkout()
    
    # 2. Écrire le nouveau code dans le fichier
    full_path = os.path.join(REPO_PATH, file_path)
    with open(full_path, "w") as f:
        f.write(new_content)
    
    # 3. Git Commit et Push
    repo.git.add(file_path)
    repo.index.commit(f"security: auto-fix for {vuln_id} [skip ci]")
    
    print(f"--- Envoi de la correction vers GitHub...")
    origin = repo.remote(name='origin')
    origin.push(branch_name)
    
    print(f"✅ Succès ! La branche {branch_name} est en ligne.")
    return branch_name

def parse_trivy_report(report_path):
    """Extrait les vulnérabilités du JSON de Trivy."""
    if not os.path.exists(report_path): return []
    with open(report_path, 'r') as f:
        data = json.load(f)
    
    vulns = []
    if 'Results' in data:
        for res in data['Results']:
            if 'Vulnerabilities' in res:
                for v in res['Vulnerabilities']:
                    if v['Severity'] in ['CRITICAL', 'HIGH']:
                        vulns.append({'id': v['VulnerabilityID'], 'file': res['Target'], 'desc': v['Title']})
    return vulns

if __name__ == "__main__":
    print("🤖 Démarrage du robot de remédiation...")
    vulnerabilities = parse_trivy_report(REPORT_PATH)
    
    if vulnerabilities:
        # On traite la première faille pour l'exemple
        target = vulnerabilities[0]
        print(f"Analyse de la faille {target['id']} dans {target['file']}...")
        
        # Lire le code actuel
        with open(os.path.join(REPO_PATH, target['file']), "r") as f:
            old_code = f.read()
            
        # Obtenir la correction
        print("Interrogation de l'IA (Llama 3)...")
        new_code = get_ai_correction(target['desc'], old_code)
        
        if new_code:
            # Nettoyer la réponse (enlever les balises ```python si présentes)
            clean_code = new_code.replace("```python", "").replace("```", "").strip()
            
            # Appliquer et Push
            apply_fix_and_push(target['file'], clean_code, target['id'])
    else:
        print("Aucune faille à corriger.")
