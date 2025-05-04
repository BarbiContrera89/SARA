#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generador de reportes HTML para SARA
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import re
from jinja2 import Environment, FileSystemLoader, select_autoescape

def generar_reporte_html(resultados: Dict[str, Any], config: Dict[str, Any], target: str, perfil: str, knowledge_base=None) -> str:
    """
    Genera un reporte HTML con los resultados del escaneo usando Jinja2.
    
    Args:
        resultados: Diccionario con los resultados de cada herramienta
        config: Configuración del escaneo
        target: IP o dominio objetivo
        perfil: Perfil de escaneo utilizado
        knowledge_base: Base de conocimiento para searchsploit
        
    Returns:
        str: Ruta al archivo HTML generado
    """
    resumen = {
        'total': len(resultados),
        'exito': sum(1 for r in resultados.values() if not isinstance(r, dict) or 'error' not in r),
        'error': sum(1 for r in resultados.values() if isinstance(r, dict) and 'error' in r)
    }
    herramientas = []
    for herramienta, resultado in resultados.items():
        data = {
            'nombre': herramienta,
            'error': None,
            'raw_output': None,
            'html_report': None
        }
        if isinstance(resultado, dict):
            if 'error' in resultado:
                data['error'] = resultado['error']
            if 'html_report' in resultado:
                data['html_report'] = resultado['html_report']
            if 'raw_output' in resultado:
                data['raw_output'] = resultado['raw_output']
        herramientas.append(data)

    # Procesar exploits para la sección de searchsploit
    exploits_con_resultados = []
    exploits_sin_resultados = []
    if knowledge_base:
        for port, info in knowledge_base.items():
            exploits = info.get('searchsploit', '').strip()
            has_results = info.get('searchsploit_has_results', False)
            raw_cmd = info.get('searchsploit_cmd', '')
            if has_results:
                exploits_html_content = re.sub(r'(https?://\S+)', r'<a href="\1" target="_blank">\1</a>', exploits)
                exploits_con_resultados.append({
                    'port': port,
                    'software': info.get('software',''),
                    'version': info.get('version',''),
                    'cmd': raw_cmd,
                    'exploits_html_content': exploits_html_content,
                    'exploits_raw': exploits
                })
            else:
                exploits_sin_resultados.append({
                    'port': port,
                    'software': info.get('software',''),
                    'version': info.get('version',''),
                    'cmd': raw_cmd
                })

    # Cargar plantilla Jinja2
    env = Environment(
        loader=FileSystemLoader('.'),
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.get_template('reporte_template.html.j2')

    contenido_html = template.render(
        target=target,
        perfil=perfil,
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        resumen=resumen,
        herramientas=herramientas,
        exploits_con_resultados=exploits_con_resultados,
        exploits_sin_resultados=exploits_sin_resultados
    )

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