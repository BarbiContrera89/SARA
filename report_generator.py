#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generador de reportes HTML
Autor: [Tu Nombre]
Fecha: [Fecha]
Descripción: Genera reportes HTML a partir de los resultados del escaneo
"""

import os
from datetime import datetime
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Escaneo - {{ target }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #333;
        }
        .timestamp {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 20px;
        }
        .profile {
            margin-bottom: 30px;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }
        .tool {
            margin-bottom: 20px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .tool h3 {
            margin-top: 0;
            color: #2c3e50;
        }
        .results-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        .results-table th, .results-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .results-table th {
            background-color: #f2f2f2;
        }
        .error {
            color: #e74c3c;
            background-color: #fde8e8;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
        }
        .success {
            color: #27ae60;
        }
        .summary {
            margin-top: 20px;
            padding: 15px;
            background-color: #e8f4f8;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Reporte de Escaneo</h1>
        <div class="timestamp">Generado el: {{ timestamp }}</div>
        <div class="summary">
            <h2>Resumen</h2>
            <p>Objetivo: {{ target }}</p>
            <p>Perfil de escaneo: {{ profile }}</p>
            <p>Total de herramientas ejecutadas: {{ total_tools }}</p>
            <p>Herramientas con éxito: {{ success_count }}</p>
            <p>Herramientas con error: {{ error_count }}</p>
        </div>

        {% for profile_name, tools in profiles.items() %}
        <div class="profile">
            <h2>Perfil: {{ profile_name }}</h2>
            {% for tool_name, result in tools.items() %}
            <div class="tool">
                <h3>{{ tool_name }}</h3>
                {% if result.error %}
                <div class="error">
                    <strong>Error:</strong> {{ result.error }}
                </div>
                {% else %}
                <table class="results-table">
                    {% for key, value in result.items() %}
                    {% if key != 'raw_output' %}
                    <tr>
                        <th>{{ key }}</th>
                        <td>{{ value }}</td>
                    </tr>
                    {% endif %}
                    {% endfor %}
                </table>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
"""

def generar_reporte_html(resultados, config, target, profile):
    """
    Genera un reporte HTML con los resultados del escaneo.
    
    Args:
        resultados (dict): Resultados del escaneo
        config (dict): Configuración del escaneo
        target (str): Objetivo del escaneo
        profile (str): Perfil de escaneo utilizado
    """
    # Preparar datos para el template
    data = {
        'target': target,
        'profile': profile,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'profiles': {},
        'total_tools': len(resultados),
        'success_count': sum(1 for r in resultados.values() if not isinstance(r, dict) or 'error' not in r),
        'error_count': sum(1 for r in resultados.values() if isinstance(r, dict) and 'error' in r)
    }
    
    # Organizar resultados por perfil
    data['profiles'][profile] = resultados
    
    # Generar HTML
    template = Template(HTML_TEMPLATE)
    html_content = template.render(**data)
    
    # Crear directorio de reportes si no existe
    os.makedirs('reportes', exist_ok=True)
    
    # Guardar archivo
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reportes/escaneo_{target}_{timestamp}.html"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filename 