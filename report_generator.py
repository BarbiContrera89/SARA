#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generador de reportes HTML para SARA
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import re

def generar_reporte_html(resultados: Dict[str, Any], config: Dict[str, Any], target: str, perfil: str, knowledge_base=None) -> str:
    """
    Genera un reporte HTML con los resultados del escaneo.
    
    Args:
        resultados: Diccionario con los resultados de cada herramienta
        config: Configuración del escaneo
        target: IP o dominio objetivo
        perfil: Perfil de escaneo utilizado
        knowledge_base: Base de conocimiento para searchsploit
        
    Returns:
        str: Ruta al archivo HTML generado
    """
    # Generar el contenido HTML
    contenido_html = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reporte de Escaneo SARA</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                color: #333;
                background-color: #f5f5f5;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }}
            .header {{
                background-color: #2c3e50;
                color: white;
                padding: 20px;
                border-radius: 5px;
                margin-bottom: 20px;
            }}
            .result-section {{
                margin-bottom: 30px;
                padding: 15px;
                border: 1px solid #ddd;
                border-radius: 5px;
                background-color: #fff;
            }}
            h1, h2, h3, h4 {{
                color: #2c3e50;
                margin-top: 0;
            }}
            .header h1 {{
                color: white;
                margin: 0;
            }}
            ul {{
                list-style-type: none;
                padding-left: 20px;
            }}
            li {{
                margin-bottom: 5px;
                padding: 5px;
                border-left: 3px solid #3498db;
            }}
            .vulnerability {{
                color: #e74c3c;
                border-left-color: #e74c3c;
            }}
            .warning {{
                color: #f39c12;
                border-left-color: #f39c12;
            }}
            .info {{
                color: #3498db;
                border-left-color: #3498db;
            }}
            .timestamp {{
                color: #bdc3c7;
                font-size: 0.9em;
                margin-top: 10px;
            }}
            .summary {{
                background-color: #ecf0f1;
                padding: 15px;
                border-radius: 5px;
                margin-bottom: 20px;
            }}
            .tool-status {{
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 0.8em;
                margin-left: 10px;
            }}
            .success {{
                background-color: #2ecc71;
                color: white;
            }}
            .error {{
                background-color: #e74c3c;
                color: white;
            }}
            a {{
                color: #3498db;
                text-decoration: none;
            }}
            a:hover {{
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Reporte de Escaneo SARA</h1>
                <p><strong>Objetivo:</strong> {target}</p>
                <p><strong>Perfil:</strong> {perfil}</p>
                <p class="timestamp">Generado el: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Resumen del Escaneo</h2>
                <p>Total de herramientas ejecutadas: {len(resultados)}</p>
                <p>Herramientas con éxito: {sum(1 for r in resultados.values() if not isinstance(r, dict) or 'error' not in r)}</p>
                <p>Herramientas con error: {sum(1 for r in resultados.values() if isinstance(r, dict) and 'error' in r)}</p>
            </div>
    """

    # Añadir resultados de cada herramienta
    for herramienta, resultado in resultados.items():
        if isinstance(resultado, dict) and 'html_report' in resultado:
            contenido_html += resultado['html_report']
        elif hasattr(resultado, 'html_report'):
            contenido_html += resultado.html_report
        elif isinstance(resultado, dict) and 'error' in resultado:
            contenido_html += f"""
            <div class="result-section">
                <h3>{herramienta}</h3>
                <div class="error">
                    <p>Error: {resultado['error']}</p>
                </div>
            </div>
            """
        else:
            contenido_html += f"""
            <div class="result-section">
                <h3>{herramienta}</h3>
                <pre>{str(resultado)}</pre>
            </div>
            """

    # Añadir sección de exploits si knowledge_base tiene searchsploit
    if knowledge_base:
        exploits_html = """
        <div class="result-section exploits-section">
            <h3>Resultados de Searchsploit por puerto/servicio</h3>
        """
        sin_resultados = []
        for port, info in knowledge_base.items():
            exploits = info.get('searchsploit', '').strip()
            has_results = info.get('searchsploit_has_results', False)
            raw_cmd = info.get('searchsploit_cmd', '')
            if has_results:
                # Hacer URLs clickeables
                exploits_html_content = re.sub(r'(https?://\S+)', r'<a href="\1" target="_blank">\1</a>', exploits)
                exploits_html += f'''
                <details class="raw-output-block" style="margin-bottom:30px;">
                  <summary style="cursor:pointer;font-weight:bold;">{port} - {info.get('software','')} {info.get('version','')}</summary>
                  <div style="margin-bottom:8px;font-size:0.95em;color:#888;">Comando usado: <code>{raw_cmd}</code></div>
                  <pre style="background:#222;color:#eee;padding:10px;border-radius:6px;overflow-x:auto;max-height:400px;white-space:pre-wrap;">{exploits_html_content}</pre>
                  <details style="margin-top:8px;">
                    <summary style="cursor:pointer;font-size:0.95em;">Ver salida completa de searchsploit</summary>
                    <pre style="background:#111;color:#eee;padding:8px;border-radius:6px;overflow-x:auto;max-height:300px;white-space:pre-wrap;">{exploits}</pre>
                  </details>
                </details>
                '''
            else:
                sin_resultados.append(port)
        exploits_html += """
        </div>
        """
        if sin_resultados:
            exploits_html += """
            <div class="result-section exploits-section">
                <h4>Puertos/servicios sin exploits encontrados:</h4>
                <ul>
            """
            for port in knowledge_base:
                info = knowledge_base[port]
                if not info.get('searchsploit_has_results', False):
                    cmd = info.get('searchsploit_cmd', '')
                    exploits_html += f"<li><b>{port} - {info.get('software','')} {info.get('version','')}</b><br><span style='font-size:0.95em;color:#888;'>Comando usado: <code>{cmd}</code></span></li>"
            exploits_html += "</ul></div>"
        contenido_html += exploits_html

    # Cerrar el HTML
    contenido_html += """
        </div>
    </body>
    </html>
    """

    # Crear directorio de reportes si no existe
    reportes_dir = Path("reportes")
    reportes_dir.mkdir(exist_ok=True)

    # Generar nombre del archivo
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre_archivo = f"reporte_{target}_{timestamp}.html"
    ruta_archivo = reportes_dir / nombre_archivo

    # Guardar el reporte
    with open(ruta_archivo, "w", encoding="utf-8") as f:
        f.write(contenido_html)

    return str(ruta_archivo) 