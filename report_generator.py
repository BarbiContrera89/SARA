#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generador de reportes HTML para SARA
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any

def generar_reporte_html(resultados: Dict[str, Any], config: Dict[str, Any], target: str, perfil: str) -> str:
    """
    Genera un reporte HTML con los resultados del escaneo.
    
    Args:
        resultados: Diccionario con los resultados de cada herramienta
        config: Configuración del escaneo
        target: IP o dominio objetivo
        perfil: Perfil de escaneo utilizado
        
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
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            .header {{
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 5px;
                margin-bottom: 20px;
            }}
            .result-section {{
                margin-bottom: 30px;
                padding: 15px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }}
            h1, h2, h3, h4 {{
                color: #2c3e50;
            }}
            ul {{
                list-style-type: none;
                padding-left: 20px;
            }}
            li {{
                margin-bottom: 5px;
            }}
            .vulnerability {{
                color: #e74c3c;
            }}
            .warning {{
                color: #f39c12;
            }}
            .info {{
                color: #3498db;
            }}
            .timestamp {{
                color: #7f8c8d;
                font-size: 0.9em;
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
    """

    # Añadir resultados de cada herramienta
    for herramienta, resultado in resultados.items():
        if hasattr(resultado, 'html_parse'):
            contenido_html += resultado.html_parse()

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