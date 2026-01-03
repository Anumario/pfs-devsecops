# 🛡️ Pipeline DevSecOps Self-Healing assisté par IA (Llama 3)

Ce projet implémente une chaîne CI/CD automatisée capable de détecter des vulnérabilités critiques 
dans une application Flask et de proposer des correctifs automatiques via un LLM local.

## 🚀 Architecture
- **Target :** Application Flask (vulnérabilités SQLi, Secrets, Root User).
- **Watcher :** GitHub Actions + Trivy (Scan de sécurité).
- **Brain :** Ollama + Llama 3 (Analyse et remédiation).
- **Fixer :** Script Python (GitPython) créant des Pull Requests automatiques.

## 🛠️ Installation
1. **Prérequis :** Ubuntu 22.04, Docker, Python 3.10+, Ollama.
2. **Installer Ollama :** `curl -fsSL https://ollama.com/install.sh | sh`
3. **Télécharger le modèle :** `ollama pull llama3`
4. **Configuration Python :**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r app/requirements.txt
   pip install GitPython requests
