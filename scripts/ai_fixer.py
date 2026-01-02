import json
import requests
import os

# Configuration
OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3"
REPORT_PATH = "scan-report.json"

def get_ai_correction(vulnerability_detail, code_contexte):
    """Envoie la faille à Llama 3 et récupère le code corrigé."""
    
    prompt = f"""
    Tu es un expert en sécurité informatique DevSecOps.
    Une faille de sécurité a été détectée par Trivy :
    Détails de la faille : {vulnerability_detail}
    
    Voici le code concerné :
    {code_contexte}
    
    Instructions :
    1. Analyse la faille.
    2. Propose UNIQUEMENT le code Python corrigé.
    3. Ne donne pas d'explications superflues, juste le bloc de code.
    """
    
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_API_URL, json=payload)
        response.raise_for_status()
        return response.json().get('response', 'Erreur de réponse IA')
    except Exception as e:
        return f"Erreur lors de l'appel à Ollama : {e}"

def parse_trivy_report(report_path):
    """Extrait les vulnérabilités critiques du rapport JSON."""
    if not os.path.exists(report_path):
        print(f"Erreur : Le fichier {report_path} n'existe pas.")
        return []

    with open(report_path, 'r') as f:
        data = json.load(f)
    
    vulns_found = []
    # On parcourt les résultats du scan
    if 'Results' in data:
        for result in data['Results']:
            if 'Vulnerabilities' in result:
                for v in result['Vulnerabilities']:
                    # On ne traite que les failles Critiques ou High
                    if v['Severity'] in ['CRITICAL', 'HIGH']:
                        vulns_found.append({
                            'id': v['VulnerabilityID'],
                            'title': v['Title'],
                            'file': result['Target'],
                            'desc': v.get('Description', 'Pas de description')
                        })
    return vulns_found

if __name__ == "__main__":
    print("--- DÉBUT DE L'ANALYSE IA ---")
    
    # 1. Lire le rapport
    vulnerabilities = parse_trivy_report(REPORT_PATH)
    
    if not vulnerabilities:
        print("Aucune faille critique détectée. Félicitations !")
    else:
        print(f"{len(vulnerabilities)} vulnérabilités détectées.")
        
        # 2. Pour l'exemple, on traite la première faille trouvée
        v = vulnerabilities[0]
        print(f"Traitement de : {v['id']} - {v['title']}")
        
        # 3. Demander la correction à l'IA
        # (Dans un vrai projet, on lirait le contenu du fichier v['file'])
        fake_context = "app.py avec injection SQL" 
        correction = get_ai_correction(v['desc'], fake_context)
        
        print("\n--- SUGGESTION DE CORRECTION DE L'IA ---")
        print(correction)
        print("---------------------------------------")
