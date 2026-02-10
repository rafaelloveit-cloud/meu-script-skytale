import requests
import os
import sys
import tempfile
from datetime import datetime

# ================== CONFIGURAÇÕES ==================  print("Nova funcionalidade!")
GITHUB_USER = "SEU_USUARIO_AQUI"          # ← Troque pelo seu username do GitHub
GITHUB_REPO = "meu-script-atualizavel"    # ← Troque pelo nome do seu repositório

VERSION_URL = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/version.txt"
SCRIPT_URL  = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/meu_script.py"

CURRENT_VERSION = "1.0.0"   # Mantenha sincronizado com o version.txt
# ===================================================

def verificar_atualizacao():
    """Verifica se tem atualização e atualiza o script automaticamente"""
    print("🔍 Verificando atualizações...")

    try:
        # Pega a versão mais recente
        versao_remota = requests.get(VERSION_URL, timeout=10).text.strip()
        
        if versao_remota <= CURRENT_VERSION:
            print(f"✅ Você já está na versão mais recente ({CURRENT_VERSION})")
            return False
            
        print(f"🔥 Nova versão disponível: {versao_remota} (atual: {CURRENT_VERSION})")
        
        # Baixa o novo script para um arquivo temporário
        resposta = requests.get(SCRIPT_URL, timeout=15)
        resposta.raise_for_status()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.py', mode='w', encoding='utf-8') as tmp:
            tmp.write(resposta.text)
            novo_arquivo = tmp.name
        
        script_atual = sys.argv[0]
        
        # Faz backup do script antigo
        backup = script_atual + ".old"
        if os.path.exists(backup):
            os.remove(backup)
        os.rename(script_atual, backup)
        
        # Substitui pelo novo
        os.rename(novo_arquivo, script_atual)
        
        print("✅ Atualização baixada com sucesso!")
        print("🔄 Reiniciando o script com a nova versão...\n")
        
        # Reinicia o script
        os.execv(sys.executable, [sys.executable] + sys.argv)
        
    except Exception as e:
        print(f"⚠️ Erro ao verificar atualização: {e}")
        return False


# ====================== SEU CÓDIGO AQUI ======================
if __name__ == "__main__":
    verificar_atualizacao()
    
    print("="*50)
    print("🚀 Meu Script Incrível - Versão", CURRENT_VERSION)
    print("="*50)
    print("Este script se atualiza automaticamente!")
    print("Teste: mude a versão no GitHub e rode novamente.\n")
    
    # Aqui vai o resto do seu código normal...
    input("Pressione Enter para fechar...")
