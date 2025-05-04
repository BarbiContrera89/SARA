#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de parseo de resultados para SARA
Contiene los parsers para cada herramienta de escaneo
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


class Parser:
    """Clase base para todos los parsers"""
    def __init__(self, output: str):
        self.output = output

    def parse(self) -> dict:
        raise NotImplementedError("Los parsers deben implementar este método")

    def generate_html(self, data: dict) -> str:
        raise NotImplementedError("Los parsers deben implementar este método")

    def _collapsible_raw_output(self, raw_output):
        return f'''
        <details class="raw-output-block">
          <summary style="cursor:pointer;font-weight:bold;">Ver salida completa (raw_output)</summary>
          <pre style="background:#222;color:#eee;padding:10px;border-radius:6px;overflow-x:auto;max-height:400px;">{raw_output}</pre>
        </details>
        '''


class NmapParser(Parser):
    def parse(self, knowledge_base=None) -> dict:
        if knowledge_base is None:
            knowledge_base = {}
        puertos_abiertos = []
        servicios_detectados = []
        sistema_operativo = None
        puerto_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\w+)(\s+(.+))?"
        os_pattern = r"OS details: (.+)"
        for line in self.output.split('\n'):
            puerto_match = re.search(puerto_pattern, line)
            if puerto_match:
                puerto = puerto_match.group(1)
                protocolo = puerto_match.group(2)
                servicio = puerto_match.group(3)
                resto = puerto_match.group(5) if puerto_match.group(5) else ''
                version = 'No detectada'
                detalles = ''
                if resto:
                    version = resto.strip()
                puertos_abiertos.append({
                    "puerto": puerto,
                    "protocolo": protocolo,
                    "estado": "open"
                })
                servicios_detectados.append({
                    "puerto": puerto,
                    "servicio": servicio,
                    "version": version,
                    "detalles": detalles
                })
                key = f"{puerto}/{protocolo}"
                knowledge_base[key] = {
                    "software": servicio,
                    "version": version,
                    "vulnerabilities": []
                }
            os_match = re.search(os_pattern, line)
            if os_match:
                sistema_operativo = os_match.group(1)
        result = {
            "puertos_abiertos": puertos_abiertos,
            "servicios_detectados": servicios_detectados,
            "sistema_operativo": sistema_operativo,
            "raw_output": self.output,
            "open_ports_info": knowledge_base
        }
        result["html_report"] = self.generate_html(result)
        return result

    def generate_html(self, data: dict) -> str:
        # Agrupar puertos y servicios en una tabla
        tabla_puertos = """
        <table class="nmap-table">
            <thead>
                <tr>
                    <th>Puerto</th>
                    <th>Protocolo</th>
                    <th>Estado</th>
                    <th>Servicio</th>
                    <th>Versión</th>
                    <th>Detalles</th>
                </tr>
            </thead>
            <tbody>
        """
        for puerto, servicio in zip(data["puertos_abiertos"], data["servicios_detectados"]):
            tabla_puertos += f"""
                <tr>
                    <td>{puerto['puerto']}</td>
                    <td>{puerto['protocolo']}</td>
                    <td><span class='port-status'>{puerto['estado'].capitalize()}</span></td>
                    <td>{servicio['servicio']}</td>
                    <td>{servicio.get('version', 'No detectada')}</td>
                    <td>{servicio.get('detalles', '')}</td>
                </tr>
            """
        tabla_puertos += """
            </tbody>
        </table>
        """

        # Sección de sistema operativo
        os_html = ""
        if data["sistema_operativo"]:
            os_html = f"""
            <div class="os-section">
                <h4>Sistema Operativo Detectado</h4>
                <div class="os-card">
                    <div class="os-details">
                        <p>{data["sistema_operativo"]}</p>
                    </div>
                </div>
            </div>
            """
        
        html = f"""
        <div class="result-section nmap-result">
            <div class="nmap-container">
                <h3>Resultados de Nmap</h3>
                <div class="scan-summary">
                    <div class="summary-item">
                        <span class="label">Puertos Escaneados:</span>
                        <span class="value">{len(data["puertos_abiertos"])}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Servicios Detectados:</span>
                        <span class="value">{len(data["servicios_detectados"])}</span>
                    </div>
                </div>
                {tabla_puertos}
                {os_html}
            </div>
            <style>
                .nmap-result {{
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .nmap-container {{
                    background-color: white;
                    border-radius: 6px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                }}
                .scan-summary {{
                    display: flex;
                    gap: 20px;
                    margin-bottom: 20px;
                    padding: 15px;
                    background-color: #e9ecef;
                    border-radius: 6px;
                }}
                .summary-item {{
                    display: flex;
                    flex-direction: column;
                }}
                .label {{
                    font-weight: bold;
                    color: #495057;
                }}
                .value {{
                    font-size: 1.2em;
                    color: #2c3e50;
                }}
                .nmap-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }}
                .nmap-table th, .nmap-table td {{
                    border: 1px solid #dee2e6;
                    padding: 8px 12px;
                    text-align: left;
                }}
                .nmap-table th {{
                    background-color: #2c3e50;
                    color: #fff;
                }}
                .nmap-table tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                .port-status {{
                    background-color: #28a745;
                    color: white;
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-size: 0.95em;
                }}
                .os-section {{
                    margin-top: 20px;
                }}
                .os-card {{
                    background-color: #e9ecef;
                    border-radius: 6px;
                    padding: 15px;
                }}
                .os-details {{
                    color: #495057;
                }}
            </style>
        </div>
        """
        html += self._collapsible_raw_output(data['raw_output'])
        return html

class NiktoParser(Parser):
    def parse(self) -> dict:
        vulnerabilidades = []
        advertencias = []
        informacion = []

        # Patrones para diferentes tipos de resultados
        vuln_pattern = r"\+ (Vulnerability|VULNERABLE): (.+)"
        warning_pattern = r"\+ (Warning|WARNING): (.+)"
        info_pattern = r"\+ (Info|INFO): (.+)"

        for line in self.output.split('\n'):
            if re.search(vuln_pattern, line):
                match = re.search(vuln_pattern, line)
                vulnerabilidades.append({
                    "tipo": match.group(1),
                    "descripcion": match.group(2)
                })
            elif re.search(warning_pattern, line):
                match = re.search(warning_pattern, line)
                advertencias.append({
                    "tipo": match.group(1),
                    "descripcion": match.group(2)
                })
            elif re.search(info_pattern, line):
                match = re.search(info_pattern, line)
                informacion.append({
                    "tipo": match.group(1),
                    "descripcion": match.group(2)
                })

        result = {
            "vulnerabilidades": vulnerabilidades,
            "advertencias": advertencias,
            "informacion": informacion,
            "raw_output": self.output
        }
        
        result["html_report"] = self.generate_html(result)
        return result

    def generate_html(self, data: dict) -> str:
        # Generar sección de vulnerabilidades
        vuln_html = """
        <div class="vulnerabilities-section">
            <h4>Vulnerabilidades Detectadas</h4>
            <div class="vulnerabilities-list">
        """
        
        if data["vulnerabilidades"]:
            for vuln in data["vulnerabilidades"]:
                vuln_html += f"""
                <div class="vulnerability-item">
                    <div class="vulnerability-header">
                        <span class="vulnerability-icon">⚠️</span>
                        <span class="vulnerability-type">{vuln['tipo']}</span>
                    </div>
                    <div class="vulnerability-description">
                        {vuln['descripcion']}
                    </div>
                </div>
                """
        else:
            vuln_html += """
                <div class="no-vulnerabilities">
                    No se detectaron vulnerabilidades críticas
                </div>
            """
        
        vuln_html += """
            </div>
        </div>
        """
        
        # Generar sección de advertencias
        warning_html = """
        <div class="warnings-section">
            <h4>Advertencias de Seguridad</h4>
            <div class="warnings-list">
        """
        
        if data["advertencias"]:
            for warning in data["advertencias"]:
                warning_html += f"""
                <div class="warning-item">
                    <div class="warning-header">
                        <span class="warning-icon">ℹ️</span>
                        <span class="warning-type">{warning['tipo']}</span>
                    </div>
                    <div class="warning-description">
                        {warning['descripcion']}
                    </div>
                </div>
                """
        else:
            warning_html += """
                <div class="no-warnings">
                    No se detectaron advertencias de seguridad
                </div>
            """
        
        warning_html += """
            </div>
        </div>
        """
        
        # Generar sección de información
        info_html = """
        <div class="info-section">
            <h4>Información Adicional</h4>
            <div class="info-list">
        """
        
        if data["informacion"]:
            for info in data["informacion"]:
                info_html += f"""
                <div class="info-item">
                    <div class="info-header">
                        <span class="info-icon">📋</span>
                        <span class="info-type">{info['tipo']}</span>
                    </div>
                    <div class="info-description">
                        {info['descripcion']}
                    </div>
                </div>
                """
        else:
            info_html += """
                <div class="no-info">
                    No se encontró información adicional
                </div>
            """
        
        info_html += """
            </div>
        </div>
        """
        
        html = f"""
        <div class="result-section nikto-result">
            <h3>Resultados de Nikto</h3>
            {vuln_html}
            {warning_html}
            {info_html}
            <style>
                .nikto-result {{
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                .vulnerabilities-section,
                .warnings-section,
                .info-section {{
                    margin-bottom: 20px;
                }}
                .vulnerabilities-list,
                .warnings-list,
                .info-list {{
                    display: flex;
                    flex-direction: column;
                    gap: 15px;
                }}
                .vulnerability-item,
                .warning-item,
                .info-item {{
                    background-color: white;
                    border-radius: 6px;
                    padding: 15px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .vulnerability-header,
                .warning-header,
                .info-header {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    margin-bottom: 10px;
                }}
                .vulnerability-icon,
                .warning-icon,
                .info-icon {{
                    font-size: 1.2em;
                }}
                .vulnerability-type,
                .warning-type,
                .info-type {{
                    font-weight: bold;
                    color: #2c3e50;
                }}
                .vulnerability-description,
                .warning-description,
                .info-description {{
                    color: #495057;
                    line-height: 1.5;
                }}
                .no-vulnerabilities,
                .no-warnings,
                .no-info {{
                    padding: 15px;
                    text-align: center;
                    color: #6c757d;
                    background-color: #f8f9fa;
                    border-radius: 4px;
                }}
            </style>
        </div>
        """
        html += self._collapsible_raw_output(data['raw_output'])
        return html

class DirbParser(Parser):
    def parse(self) -> dict:
        directorios_encontrados = []
        archivos_encontrados = []

        # Patrones para directorios y archivos
        dir_pattern = r"\+ (DIRECTORY): (.+)"
        file_pattern = r"\+ (FILE): (.+)"

        for line in self.output.split('\n'):
            if re.search(dir_pattern, line):
                match = re.search(dir_pattern, line)
                directorios_encontrados.append({
                    "tipo": match.group(1),
                    "ruta": match.group(2)
                })
            elif re.search(file_pattern, line):
                match = re.search(file_pattern, line)
                archivos_encontrados.append({
                    "tipo": match.group(1),
                    "ruta": match.group(2)
                })

        result = {
            "directorios_encontrados": directorios_encontrados,
            "archivos_encontrados": archivos_encontrados,
            "raw_output": self.output
        }
        
        result["html_report"] = self.generate_html(result)
        return result

    def generate_html(self, data: dict) -> str:
        # Generar sección de directorios
        dirs_html = """
        <div class="directories-section">
            <h4>Directorios Encontrados</h4>
            <div class="directories-list">
        """
        
        if data["directorios_encontrados"]:
            for dir_info in data["directorios_encontrados"]:
                dirs_html += f"""
                <div class="directory-item">
                    <div class="directory-header">
                        <span class="directory-icon">📁</span>
                        <span class="directory-path">{dir_info['ruta']}</span>
                    </div>
                    <div class="directory-details">
                        <span class="directory-type">{dir_info['tipo']}</span>
                    </div>
                </div>
                """
        else:
            dirs_html += """
                <div class="no-directories">
                    No se encontraron directorios
                </div>
            """
        
        dirs_html += """
            </div>
        </div>
        """
        
        # Generar sección de archivos
        files_html = """
        <div class="files-section">
            <h4>Archivos Encontrados</h4>
            <div class="files-list">
        """
        
        if data["archivos_encontrados"]:
            for file_info in data["archivos_encontrados"]:
                files_html += f"""
                <div class="file-item">
                    <div class="file-header">
                        <span class="file-icon">📄</span>
                        <span class="file-path">{file_info['ruta']}</span>
                    </div>
                    <div class="file-details">
                        <span class="file-type">{file_info['tipo']}</span>
                    </div>
                </div>
                """
        else:
            files_html += """
                <div class="no-files">
                    No se encontraron archivos
                </div>
            """
        
        files_html += """
            </div>
        </div>
        """
        
        html = f"""
        <div class="result-section dirb-result">
            <h3>Resultados de Dirb</h3>
            {dirs_html}
            {files_html}
            <style>
                .dirb-result {{
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                .directories-section,
                .files-section {{
                    margin-bottom: 20px;
                }}
                .directories-list,
                .files-list {{
                    display: flex;
                    flex-direction: column;
                    gap: 15px;
                }}
                .directory-item,
                .file-item {{
                    background-color: white;
                    border-radius: 6px;
                    padding: 15px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .directory-header,
                .file-header {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    margin-bottom: 10px;
                }}
                .directory-icon,
                .file-icon {{
                    font-size: 1.2em;
                }}
                .directory-path,
                .file-path {{
                    font-weight: bold;
                    color: #2c3e50;
                }}
                .directory-details,
                .file-details {{
                    color: #495057;
                    font-size: 0.9em;
                }}
                .directory-type,
                .file-type {{
                    background-color: #e9ecef;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.8em;
                }}
                .no-directories,
                .no-files {{
                    padding: 15px;
                    text-align: center;
                    color: #6c757d;
                    background-color: #f8f9fa;
                    border-radius: 4px;
                }}
            </style>
        </div>
        """
        html += self._collapsible_raw_output(data['raw_output'])
        return html

class NmapExtendedParser(Parser):
    def parse(self, knowledge_base=None) -> dict:
        if knowledge_base is None:
            knowledge_base = {}
        puertos = []
        raw_output = self.output
        current_port = None
        current_service = None
        current_vulns = []
        port_line = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(\s+(.+))?")
        vuln_script = re.compile(r"\|\s+(.+):\s*(.*)")
        lines = self.output.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i]
            port_match = port_line.match(line)
            if port_match:
                if current_port:
                    key = f"{current_port}/{current_proto}"
                    knowledge_base[key] = {
                        "software": current_service,
                        "version": current_version,
                        "vulnerabilities": [v['script'] for v in current_vulns if v['script']]
                    }
                    puertos.append({
                        'puerto': current_port,
                        'protocolo': current_proto,
                        'servicio': current_service,
                        'version': current_version,
                        'vulns': current_vulns
                    })
                current_port = port_match.group(1)
                current_proto = port_match.group(2)
                current_service = port_match.group(3)
                current_version = port_match.group(5) if port_match.group(5) else ''
                current_vulns = []
                i += 1
                while i < len(lines) and (lines[i].startswith('|') or lines[i].startswith('|_')):
                    vuln_match = vuln_script.match(lines[i])
                    if vuln_match:
                        script_name = vuln_match.group(1)
                        script_output = vuln_match.group(2)
                        details = []
                        i += 1
                        while i < len(lines) and lines[i].startswith('|   '):
                            detail = lines[i].replace('|   ', '').strip()
                            details.append(detail)
                            i += 1
                        current_vulns.append({
                            'script': script_name,
                            'output': script_output,
                            'details': details
                        })
                    else:
                        i += 1
                continue
            i += 1
        if current_port:
            key = f"{current_port}/{current_proto}"
            knowledge_base[key] = {
                "software": current_service,
                "version": current_version,
                "vulnerabilities": [v['script'] for v in current_vulns if v['script']]
            }
            puertos.append({
                'puerto': current_port,
                'protocolo': current_proto,
                'servicio': current_service,
                'version': current_version,
                'vulns': current_vulns
            })
        result = {
            'puertos': puertos,
            'raw_output': raw_output,
            'open_ports_info': knowledge_base
        }
        result['html_report'] = self.generate_html(result)
        return result

    def generate_html(self, data: dict) -> str:
        tabla = """
        <table class="nmap-table">
            <thead>
                <tr>
                    <th>Puerto</th>
                    <th>Protocolo</th>
                    <th>Servicio</th>
                    <th>Versión</th>
                    <th>Vulnerabilidades detectadas</th>
                </tr>
            </thead>
            <tbody>
        """
        for p in data['puertos']:
            vulns_html = ""
            if p['vulns']:
                for v in p['vulns']:
                    vulns_html += f"<div class='vuln-script'><b>{v['script']}</b>: {v['output']}"
                    if v['details']:
                        vulns_html += "<ul>"
                        for d in v['details']:
                            vulns_html += f"<li>{d}</li>"
                        vulns_html += "</ul>"
                    vulns_html += "</div>"
            else:
                vulns_html = "<span class='no-vulns'>Sin hallazgos</span>"
            tabla += f"""
                <tr>
                    <td>{p['puerto']}</td>
                    <td>{p['protocolo']}</td>
                    <td>{p['servicio']}</td>
                    <td>{p['version']}</td>
                    <td>{vulns_html}</td>
                </tr>
            """
        tabla += """
            </tbody>
        </table>
        """
        html = f"""
        <div class="result-section nmap-extended-result">
            <div class="nmap-container">
                <h3>Resultados de Nmap (Vulnerabilidades)</h3>
                {tabla}
            </div>
            <style>
                .nmap-extended-result {{
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .nmap-container {{
                    background-color: white;
                    border-radius: 6px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                }}
                .nmap-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }}
                .nmap-table th, .nmap-table td {{
                    border: 1px solid #dee2e6;
                    padding: 8px 12px;
                    text-align: left;
                }}
                .nmap-table th {{
                    background-color: #2c3e50;
                    color: #fff;
                }}
                .nmap-table tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                .vuln-script {{
                    margin-bottom: 8px;
                    padding: 6px 8px;
                    background: #fff3cd;
                    border-left: 4px solid #ffc107;
                    border-radius: 4px;
                }}
                .no-vulns {{
                    color: #28a745;
                    font-weight: bold;
                }}
            </style>
        </div>
        """
        html += self._collapsible_raw_output(data['raw_output'])
        return html

# Diccionario de parsers disponibles
PARSERS = {
    'nmap': NmapParser,
    'nikto': NiktoParser,
    'dirb': DirbParser,
    'nmap_extended': NmapExtendedParser,
} 