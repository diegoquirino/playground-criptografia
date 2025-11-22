#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Servidor HTTP/HTTPS com Tela de Login para Demonstração com Wireshark
Autor: Playground de Criptografia
Descrição: Cria um servidor duplo (HTTP e HTTPS) com tela de login simples
           para demonstrar a diferença entre tráfego criptografado e não criptografado.
"""

import os
import sys
import ssl
import subprocess
from flask import Flask, request, render_template_string
from threading import Thread
from pathlib import Path

# --- Configuração do Aplicativo Flask ---
app = Flask(__name__)

# --- Template HTML da Tela de Login ---
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tela de Login - {{ protocol }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-container { 
            background-color: white;
            padding: 50px;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
            width: 350px;
            text-align: center;
        }
        .protocol-indicator {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .protocol-http { 
            background-color: #ffe5e5;
            color: #d9534f;
        }
        .protocol-https { 
            background-color: #e5f5e5;
            color: #5cb85c;
        }
        h1 { 
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        p { 
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 15px;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        input { 
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button { 
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 6px;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .btn-http { background-color: #d9534f; }
        .btn-https { background-color: #5cb85c; }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="protocol-indicator protocol-{{ protocol.lower() }}">
            Conexão via {{ protocol }}
        </div>
        <h1>Tela de Login</h1>
        <p>Use Wireshark para analisar esta conexão.</p>
        {% if protocol == 'HTTP' %}
        <div class="warning">
            ⚠️ Aviso: Esta conexão NÃO é criptografada. Seus dados podem ser interceptados!
        </div>
        {% else %}
        <div class="warning">
            ✓ Esta conexão está criptografada com TLS/SSL.
        </div>
        {% endif %}
        <form method="post">
            <div class="form-group">
                <label for="username">Usuário:</label>
                <input type="text" id="username" name="username" placeholder="Digite seu usuário" required>
            </div>
            <div class="form-group">
                <label for="password">Senha:</label>
                <input type="password" id="password" name="password" placeholder="Digite sua senha" required>
            </div>
            <button type="submit" class="btn-{{ protocol.lower() }}">Entrar</button>
        </form>
    </div>
</body>
</html>
"""

# --- Geração do Certificado Autoassinado ---
def gerar_certificado():
    """Verifica se o certificado e a chave existem, senão, gera novos."""
    cert_path = Path("cert.pem")
    key_path = Path("key.pem")
    
    if cert_path.exists() and key_path.exists():
        print("[✓] Certificado e chave já existentes.")
        return True
    
    print("[*] Gerando certificado autoassinado (cert.pem) e chave privada (key.pem)...")
    comando = [
        "openssl", "req",
        "-x509",
        "-newkey", "rsa:4096",
        "-nodes",
        "-out", "cert.pem",
        "-keyout", "key.pem",
        "-days", "365",
        "-subj", "/CN=localhost"
    ]
    
    try:
        resultado = subprocess.run(
            comando,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print("[✓] Certificado e chave gerados com sucesso!")
        print(f"    - Arquivo: cert.pem")
        print(f"    - Arquivo: key.pem")
        print(f"    - Validade: 365 dias")
        return True
    except FileNotFoundError:
        print("[!] Erro: OpenSSL não encontrado no PATH do sistema.")
        print("[!] Instale o OpenSSL:")
        print("    - Ubuntu/Debian: sudo apt install openssl")
        print("    - CentOS/RHEL: sudo yum install openssl")
        print("    - macOS: brew install openssl")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[!] Erro ao gerar certificado: {e.stderr}")
        return False

# --- Rotas do Servidor ---
@app.route("/", methods=["GET", "POST"])
def login():
    """Rota principal que exibe a tela de login e processa o envio do formulário."""
    protocol = "HTTPS" if request.is_secure else "HTTP"
    
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        print(f"\n{'='*60}")
        print(f"[+] Credenciais recebidas via {protocol}")
        print(f"{'='*60}")
        print(f"    Usuário: {username}")
        print(f"    Senha:   {password}")
        print(f"    IP:      {request.remote_addr}")
        print(f"    User-Agent: {request.headers.get('User-Agent', 'N/A')}")
        print(f"{'='*60}\n")
        
        return f"""
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: sans-serif; text-align: center; padding: 50px; }}
                .success {{ color: #5cb85c; font-size: 24px; }}
                .info {{ color: #666; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="success">✓ Login via {protocol} bem-sucedido!</div>
            <div class="info">
                <p>Verifique o terminal onde o servidor está rodando para ver os dados recebidos.</p>
                <p><a href="/">Voltar ao login</a></p>
            </div>
        </body>
        </html>
        """
    
    return render_template_string(LOGIN_TEMPLATE, protocol=protocol)

# --- Funções para iniciar os servidores ---
def run_http_server():
    """Inicia o servidor HTTP na porta 8080."""
    try:
        print("[*] Iniciando servidor HTTP na porta 8080...")
        app.run(
            host="0.0.0.0",
            port=8080,
            debug=False,
            use_reloader=False,
            threaded=True
        )
    except OSError as e:
        print(f"[!] Erro ao iniciar servidor HTTP: {e}")

def run_https_server():
    """Inicia o servidor HTTPS na porta 8443."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("cert.pem", "key.pem")
        print("[*] Iniciando servidor HTTPS na porta 8443...")
        app.run(
            host="0.0.0.0",
            port=8443,
            debug=False,
            use_reloader=False,
            ssl_context=context,
            threaded=True
        )
    except OSError as e:
        print(f"[!] Erro ao iniciar servidor HTTPS: {e}")

# --- Bloco Principal ---
if __name__ == "__main__":
    print("\n" + "="*60)
    print("  Servidor HTTP/HTTPS com Tela de Login")
    print("  Demonstração para Wireshark")
    print("="*60 + "\n")
    
    # Verificar se Flask está instalado
    try:
        import flask
    except ImportError:
        print("[!] Erro: Flask não está instalado.")
        print("[!] Instale com: pip3 install Flask")
        sys.exit(1)
    
    # Gerar certificado
    if not gerar_certificado():
        sys.exit(1)
    
    print("\n[*] Iniciando servidores...\n")
    
    # Iniciar ambos os servidores em threads separadas
    https_thread = Thread(target=run_https_server, daemon=True)
    http_thread = Thread(target=run_http_server, daemon=True)
    
    https_thread.start()
    http_thread.start()
    
    print("\n" + "="*60)
    print("  SERVIDORES INICIADOS COM SUCESSO")
    print("="*60)
    print("\n[✓] HTTP:  http://localhost:8080")
    print("[✓] HTTPS: https://localhost:8443")
    print("\n[*] Pressione Ctrl+C para parar os servidores.\n")
    
    try:
        https_thread.join()
    except KeyboardInterrupt:
        print("\n\n[*] Servidores parados.")
        sys.exit(0)
