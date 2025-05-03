#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de parseo de resultados para SARA
Contiene los parsers para cada herramienta de escaneo
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class PingResult:
    """Resultados del comando ping"""
    paquetes_enviados: int
    paquetes_recibidos: int
    perdida_paquetes: float
    tiempo_min: float
    tiempo_avg: float
    tiempo_max: float
    raw_output: str

    def html_parse(self) -> str:
        return f"""
        <div class="result-section ping-result">
            <h3>Resultados de Ping</h3>
            <ul>
                <li>Paquetes enviados: {self.paquetes_enviados}</li>
                <li>Paquetes recibidos: {self.paquetes_recibidos}</li>
                <li>Pérdida de paquetes: {self.perdida_paquetes}%</li>
                <li>Tiempo mínimo: {self.tiempo_min} ms</li>
                <li>Tiempo promedio: {self.tiempo_avg} ms</li>
                <li>Tiempo máximo: {self.tiempo_max} ms</li>
            </ul>
        </div>
        """

@dataclass
class NmapResult:
    """Resultados del escaneo Nmap"""
    puertos_abiertos: List[Dict[str, str]]
    servicios_detectados: List[Dict[str, str]]
    sistema_operativo: Optional[str]
    raw_output: str

    def html_parse(self) -> str:
        # Categorizar puertos por servicio común
        puertos_categorizados = {
            "Web": [],
            "Base de Datos": [],
            "Correo": [],
            "Archivos": [],
            "Otros": []
        }

        for puerto, servicio in zip(self.puertos_abiertos, self.servicios_detectados):
            port_info = {
                "puerto": puerto['puerto'],
                "protocolo": puerto['protocolo'],
                "servicio": servicio['servicio'],
                "version": servicio.get('version', 'No detectada'),
                "detalles": servicio.get('detalles', '')
            }

            # Categorizar por puerto común
            if port_info['puerto'] in ['80', '443', '8080', '8443']:
                puertos_categorizados["Web"].append(port_info)
            elif port_info['puerto'] in ['3306', '5432', '27017']:
                puertos_categorizados["Base de Datos"].append(port_info)
            elif port_info['puerto'] in ['25', '110', '143', '465', '587', '993', '995']:
                puertos_categorizados["Correo"].append(port_info)
            elif port_info['puerto'] in ['21', '22', '445', '2049']:
                puertos_categorizados["Archivos"].append(port_info)
            else:
                puertos_categorizados["Otros"].append(port_info)

        # Generar HTML para cada categoría
        categorias_html = ""
        for categoria, puertos in puertos_categorizados.items():
            if puertos:
                categorias_html += f"""
                <div class="port-category">
                    <h4 class="category-title">{categoria}</h4>
                    <div class="ports-list">
                """
                
                for port_info in puertos:
                    categorias_html += f"""
                        <div class="port-card">
                            <div class="port-header">
                                <span class="port-number">{port_info['puerto']}/{port_info['protocolo']}</span>
                                <span class="port-status">Abierto</span>
                            </div>
                            <div class="port-details">
                                <div class="service-info">
                                    <span class="service-name">{port_info['servicio']}</span>
                                    {f'<span class="service-version">v{port_info["version"]}</span>' if port_info['version'] != 'No detectada' else ''}
                                </div>
                                {f'<div class="service-details">{port_info["detalles"]}</div>' if port_info['detalles'] else ''}
                            </div>
                        </div>
                    """
                
                categorias_html += """
                    </div>
                </div>
                """

        # Sección de sistema operativo
        os_html = ""
        if self.sistema_operativo:
            os_html = f"""
            <div class="os-section">
                <h4>Sistema Operativo Detectado</h4>
                <div class="os-card">
                    <div class="os-details">
                        <p>{self.sistema_operativo}</p>
                    </div>
                </div>
            </div>
            """
        
        return f"""
        <div class="result-section nmap-result">
            <div class="nmap-container">
                <h3>Resultados de Nmap</h3>
                <div class="scan-summary">
                    <div class="summary-item">
                        <span class="label">Puertos Escaneados:</span>
                        <span class="value">{len(self.puertos_abiertos)}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Servicios Detectados:</span>
                        <span class="value">{len(self.servicios_detectados)}</span>
                    </div>
                </div>
                {categorias_html}
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
                .port-category {{
                    margin: 20px 0;
                }}
                .category-title {{
                    color: #2c3e50;
                    margin-bottom: 15px;
                    padding-bottom: 5px;
                    border-bottom: 2px solid #e9ecef;
                }}
                .ports-list {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                    gap: 15px;
                }}
                .port-card {{
                    background-color: white;
                    border-radius: 6px;
                    padding: 15px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    transition: transform 0.2s;
                }}
                .port-card:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
                }}
                .port-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 10px;
                }}
                .port-number {{
                    font-weight: bold;
                    color: #2c3e50;
                    font-size: 1.1em;
                }}
                .port-status {{
                    background-color: #28a745;
                    color: white;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.9em;
                }}
                .service-info {{
                    margin-bottom: 8px;
                }}
                .service-name {{
                    font-weight: bold;
                    color: #495057;
                }}
                .service-version {{
                    background-color: #e9ecef;
                    padding: 2px 6px;
                    border-radius: 4px;
                    margin-left: 8px;
                    font-size: 0.9em;
                }}
                .service-details {{
                    color: #6c757d;
                    font-size: 0.9em;
                    margin-top: 5px;
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

@dataclass
class WhoisResult:
    """Resultados de la consulta Whois"""
    dominio: str
    registrante: Optional[str]
    fecha_creacion: Optional[str]
    fecha_expiracion: Optional[str]
    servidores_dns: List[str]
    raw_output: str

    def html_parse(self) -> str:
        # Generar tabla de información del dominio
        dominio_html = f"""
        <div class="domain-info">
            <h4>Información del Dominio</h4>
            <div class="info-card">
                <div class="info-row">
                    <span class="info-label">Dominio:</span>
                    <span class="info-value">{self.dominio}</span>
                </div>
                {f'<div class="info-row"><span class="info-label">Registrante:</span><span class="info-value">{self.registrante}</span></div>' if self.registrante else ''}
                {f'<div class="info-row"><span class="info-label">Fecha de Creación:</span><span class="info-value">{self.fecha_creacion}</span></div>' if self.fecha_creacion else ''}
                {f'<div class="info-row"><span class="info-label">Fecha de Expiración:</span><span class="info-value">{self.fecha_expiracion}</span></div>' if self.fecha_expiracion else ''}
            </div>
        </div>
        """
        
        # Generar lista de servidores DNS
        dns_html = """
        <div class="dns-servers">
            <h4>Servidores DNS</h4>
            <div class="server-list">
        """
        
        if self.servidores_dns:
            for dns in self.servidores_dns:
                dns_html += f"""
                <div class="server-item">
                    <span class="server-icon">🌐</span>
                    <span class="server-name">{dns}</span>
                </div>
                """
        else:
            dns_html += """
                <div class="no-servers">
                    No se encontraron servidores DNS
                </div>
            """
        
        dns_html += """
            </div>
        </div>
        """
        
        return f"""
        <div class="result-section whois-result">
            <h3>Resultados de Whois</h3>
            {dominio_html}
            {dns_html}
            <style>
                .whois-result {{
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                .domain-info {{
                    margin-bottom: 20px;
                }}
                .info-card {{
                    background-color: white;
                    border-radius: 6px;
                    padding: 15px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .info-row {{
                    display: flex;
                    padding: 8px 0;
                    border-bottom: 1px solid #eee;
                }}
                .info-row:last-child {{
                    border-bottom: none;
                }}
                .info-label {{
                    font-weight: bold;
                    color: #495057;
                    width: 150px;
                }}
                .info-value {{
                    color: #2c3e50;
                }}
                .dns-servers {{
                    margin-top: 20px;
                }}
                .server-list {{
                    display: flex;
                    flex-direction: column;
                    gap: 10px;
                    margin-top: 10px;
                }}
                .server-item {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    padding: 10px;
                    background-color: white;
                    border-radius: 4px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }}
                .server-icon {{
                    font-size: 1.2em;
                }}
                .server-name {{
                    color: #2c3e50;
                }}
                .no-servers {{
                    padding: 15px;
                    text-align: center;
                    color: #6c757d;
                    background-color: #f8f9fa;
                    border-radius: 4px;
                }}
            </style>
        </div>
        """

@dataclass
class NiktoResult:
    """Resultados del escaneo Nikto"""
    vulnerabilidades: List[Dict[str, str]]
    advertencias: List[Dict[str, str]]
    informacion: List[Dict[str, str]]
    raw_output: str

    def html_parse(self) -> str:
        # Generar sección de vulnerabilidades
        vuln_html = """
        <div class="vulnerabilities-section">
            <h4>Vulnerabilidades Detectadas</h4>
            <div class="vulnerabilities-list">
        """
        
        if self.vulnerabilidades:
            for vuln in self.vulnerabilidades:
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
        
        if self.advertencias:
            for warning in self.advertencias:
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
        
        if self.informacion:
            for info in self.informacion:
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
        
        return f"""
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

@dataclass
class DirbResult:
    """Resultados del escaneo Dirb"""
    directorios_encontrados: List[Dict[str, str]]
    archivos_encontrados: List[Dict[str, str]]
    raw_output: str

    def html_parse(self) -> str:
        # Generar sección de directorios
        dirs_html = """
        <div class="directories-section">
            <h4>Directorios Encontrados</h4>
            <div class="directories-list">
        """
        
        if self.directorios_encontrados:
            for dir_info in self.directorios_encontrados:
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
        
        if self.archivos_encontrados:
            for file_info in self.archivos_encontrados:
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
        
        return f"""
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

@dataclass
class SSLScanResult:
    """Resultados del escaneo SSLScan"""
    certificado: Dict[str, str]
    protocolos_soportados: List[str]
    cifrados_soportados: List[Dict[str, str]]
    vulnerabilidades: List[str]
    raw_output: str

    def html_parse(self) -> str:
        # Generar sección de certificado
        cert_html = """
        <div class="certificate-section">
            <h4>Información del Certificado</h4>
            <div class="certificate-info">
        """
        
        if self.certificado:
            for key, value in self.certificado.items():
                cert_html += f"""
                <div class="certificate-item">
                    <span class="certificate-label">{key}:</span>
                    <span class="certificate-value">{value}</span>
                </div>
                """
        else:
            cert_html += """
                <div class="no-certificate">
                    No se encontró información del certificado
                </div>
            """
        
        cert_html += """
            </div>
        </div>
        """
        
        # Generar sección de protocolos
        protocols_html = """
        <div class="protocols-section">
            <h4>Protocolos Soportados</h4>
            <div class="protocols-list">
        """
        
        if self.protocolos_soportados:
            for protocol in self.protocolos_soportados:
                protocols_html += f"""
                <div class="protocol-item">
                    <span class="protocol-icon">🔒</span>
                    <span class="protocol-name">{protocol}</span>
                </div>
                """
        else:
            protocols_html += """
                <div class="no-protocols">
                    No se encontraron protocolos soportados
                </div>
            """
        
        protocols_html += """
            </div>
        </div>
        """
        
        # Generar sección de cifrados
        ciphers_html = """
        <div class="ciphers-section">
            <h4>Cifrados Soportados</h4>
            <div class="ciphers-list">
        """
        
        if self.cifrados_soportados:
            for cipher in self.cifrados_soportados:
                ciphers_html += f"""
                <div class="cipher-item">
                    <div class="cipher-header">
                        <span class="cipher-name">{cipher['cifrado']}</span>
                        <span class="cipher-type">{cipher['tipo']}</span>
                    </div>
                    <div class="cipher-details">
                        <span class="cipher-bits">{cipher['bits']} bits</span>
                        <span class="cipher-status">{cipher['estado']}</span>
                    </div>
                </div>
                """
        else:
            ciphers_html += """
                <div class="no-ciphers">
                    No se encontraron cifrados soportados
                </div>
            """
        
        ciphers_html += """
            </div>
        </div>
        """
        
        # Generar sección de vulnerabilidades
        vuln_html = """
        <div class="vulnerabilities-section">
            <h4>Vulnerabilidades Detectadas</h4>
            <div class="vulnerabilities-list">
        """
        
        if self.vulnerabilidades:
            for vuln in self.vulnerabilidades:
                vuln_html += f"""
                <div class="vulnerability-item">
                    <span class="vulnerability-icon">⚠️</span>
                    <span class="vulnerability-text">{vuln}</span>
                </div>
                """
        else:
            vuln_html += """
                <div class="no-vulnerabilities">
                    No se detectaron vulnerabilidades
                </div>
            """
        
        vuln_html += """
            </div>
        </div>
        """
        
        return f"""
        <div class="result-section sslscan-result">
            <h3>Resultados de SSLScan</h3>
            {cert_html}
            {protocols_html}
            {ciphers_html}
            {vuln_html}
            <style>
                .sslscan-result {{
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                .certificate-section,
                .protocols-section,
                .ciphers-section,
                .vulnerabilities-section {{
                    margin-bottom: 20px;
                }}
                .certificate-info,
                .protocols-list,
                .ciphers-list,
                .vulnerabilities-list {{
                    display: flex;
                    flex-direction: column;
                    gap: 15px;
                }}
                .certificate-item,
                .protocol-item,
                .cipher-item,
                .vulnerability-item {{
                    background-color: white;
                    border-radius: 6px;
                    padding: 15px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .certificate-label {{
                    font-weight: bold;
                    color: #2c3e50;
                    width: 150px;
                    display: inline-block;
                }}
                .certificate-value {{
                    color: #495057;
                }}
                .protocol-item,
                .vulnerability-item {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }}
                .protocol-icon,
                .vulnerability-icon {{
                    font-size: 1.2em;
                }}
                .protocol-name,
                .vulnerability-text {{
                    color: #2c3e50;
                }}
                .cipher-header {{
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 8px;
                }}
                .cipher-name {{
                    font-weight: bold;
                    color: #2c3e50;
                }}
                .cipher-type {{
                    background-color: #e9ecef;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.8em;
                }}
                .cipher-details {{
                    display: flex;
                    gap: 15px;
                    color: #495057;
                    font-size: 0.9em;
                }}
                .cipher-bits,
                .cipher-status {{
                    background-color: #f8f9fa;
                    padding: 4px 8px;
                    border-radius: 4px;
                }}
                .no-certificate,
                .no-protocols,
                .no-ciphers,
                .no-vulnerabilities {{
                    padding: 15px;
                    text-align: center;
                    color: #6c757d;
                    background-color: #f8f9fa;
                    border-radius: 4px;
                }}
            </style>
        </div>
        """

@dataclass
class Enum4linuxResult:
    """Resultados del escaneo Enum4linux"""
    usuarios: List[str]
    grupos: List[str]
    recursos_compartidos: List[str]
    informacion_sistema: Dict[str, str]
    raw_output: str

    def html_parse(self) -> str:
        # Generar sección de usuarios
        users_html = """
        <div class="users-section">
            <h4>Usuarios Encontrados</h4>
            <div class="users-list">
        """
        
        if self.usuarios:
            for user in self.usuarios:
                users_html += f"""
                <div class="user-item">
                    <span class="user-icon">👤</span>
                    <span class="user-name">{user}</span>
                </div>
                """
        else:
            users_html += """
                <div class="no-users">
                    No se encontraron usuarios
                </div>
            """
        
        users_html += """
            </div>
        </div>
        """
        
        # Generar sección de grupos
        groups_html = """
        <div class="groups-section">
            <h4>Grupos Encontrados</h4>
            <div class="groups-list">
        """
        
        if self.grupos:
            for group in self.grupos:
                groups_html += f"""
                <div class="group-item">
                    <span class="group-icon">👥</span>
                    <span class="group-name">{group}</span>
                </div>
                """
        else:
            groups_html += """
                <div class="no-groups">
                    No se encontraron grupos
                </div>
            """
        
        groups_html += """
            </div>
        </div>
        """
        
        # Generar sección de recursos compartidos
        shares_html = """
        <div class="shares-section">
            <h4>Recursos Compartidos</h4>
            <div class="shares-list">
        """
        
        if self.recursos_compartidos:
            for share in self.recursos_compartidos:
                shares_html += f"""
                <div class="share-item">
                    <span class="share-icon">📂</span>
                    <span class="share-name">{share}</span>
                </div>
                """
        else:
            shares_html += """
                <div class="no-shares">
                    No se encontraron recursos compartidos
                </div>
            """
        
        shares_html += """
            </div>
        </div>
        """
        
        # Generar sección de información del sistema
        system_html = """
        <div class="system-section">
            <h4>Información del Sistema</h4>
            <div class="system-info">
        """
        
        if self.informacion_sistema:
            for key, value in self.informacion_sistema.items():
                system_html += f"""
                <div class="system-item">
                    <span class="system-label">{key}:</span>
                    <span class="system-value">{value}</span>
                </div>
                """
        else:
            system_html += """
                <div class="no-system-info">
                    No se encontró información del sistema
                </div>
            """
        
        system_html += """
            </div>
        </div>
        """
        
        return f"""
        <div class="result-section enum4linux-result">
            <h3>Resultados de Enum4linux</h3>
            {users_html}
            {groups_html}
            {shares_html}
            {system_html}
            <style>
                .enum4linux-result {{
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                .users-section,
                .groups-section,
                .shares-section,
                .system-section {{
                    margin-bottom: 20px;
                }}
                .users-list,
                .groups-list,
                .shares-list,
                .system-info {{
                    display: flex;
                    flex-direction: column;
                    gap: 15px;
                }}
                .user-item,
                .group-item,
                .share-item,
                .system-item {{
                    background-color: white;
                    border-radius: 6px;
                    padding: 15px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .user-item,
                .group-item,
                .share-item {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }}
                .user-icon,
                .group-icon,
                .share-icon {{
                    font-size: 1.2em;
                }}
                .user-name,
                .group-name,
                .share-name {{
                    color: #2c3e50;
                }}
                .system-item {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                .system-label {{
                    font-weight: bold;
                    color: #2c3e50;
                    width: 150px;
                }}
                .system-value {{
                    color: #495057;
                }}
                .no-users,
                .no-groups,
                .no-shares,
                .no-system-info {{
                    padding: 15px;
                    text-align: center;
                    color: #6c757d;
                    background-color: #f8f9fa;
                    border-radius: 4px;
                }}
            </style>
        </div>
        """

class Parser:
    """Clase base para todos los parsers"""
    def __init__(self, output: str):
        self.output = output

    def parse(self):
        raise NotImplementedError("Los parsers deben implementar este método")

class PingParser(Parser):
    def parse(self) -> PingResult:
        # Patrones para extraer información del ping
        paquetes_pattern = r"(\d+) packets transmitted, (\d+) received, (\d+)% packet loss"
        tiempo_pattern = r"min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/[\d.]+ ms"

        paquetes_match = re.search(paquetes_pattern, self.output)
        tiempo_match = re.search(tiempo_pattern, self.output)

        if not paquetes_match or not tiempo_match:
            raise ValueError("No se pudo parsear la salida del ping")

        return PingResult(
            paquetes_enviados=int(paquetes_match.group(1)),
            paquetes_recibidos=int(paquetes_match.group(2)),
            perdida_paquetes=float(paquetes_match.group(3)),
            tiempo_min=float(tiempo_match.group(1)),
            tiempo_avg=float(tiempo_match.group(2)),
            tiempo_max=float(tiempo_match.group(3)),
            raw_output=self.output
        )

class NmapParser(Parser):
    def parse(self) -> NmapResult:
        puertos_abiertos = []
        servicios_detectados = []
        sistema_operativo = None

        # Patrones para diferentes tipos de información
        puerto_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\w+)"
        version_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\w+)\s+(.+?)(?=\n|$)"
        os_pattern = r"OS details: (.+)"

        # Procesar cada línea del output
        for line in self.output.split('\n'):
            # Buscar puertos abiertos
            puerto_match = re.search(puerto_pattern, line)
            if puerto_match:
                puertos_abiertos.append({
                    "puerto": puerto_match.group(1),
                    "protocolo": puerto_match.group(2),
                    "estado": "open"
                })
                servicios_detectados.append({
                    "puerto": puerto_match.group(1),
                    "servicio": puerto_match.group(3),
                    "version": "No detectada",
                    "detalles": ""
                })

            # Buscar información de versión
            version_match = re.search(version_pattern, line)
            if version_match:
                puerto = version_match.group(1)
                servicio = version_match.group(3)
                detalles = version_match.group(4).strip()
                
                # Actualizar la información del servicio
                for servicio_info in servicios_detectados:
                    if servicio_info['puerto'] == puerto:
                        servicio_info['servicio'] = servicio
                        if "version" in detalles.lower():
                            version_match = re.search(r"version:?\s*([^\s,]+)", detalles, re.IGNORECASE)
                            if version_match:
                                servicio_info['version'] = version_match.group(1)
                        servicio_info['detalles'] = detalles

            # Buscar información del sistema operativo
            os_match = re.search(os_pattern, line)
            if os_match:
                sistema_operativo = os_match.group(1)

        return NmapResult(
            puertos_abiertos=puertos_abiertos,
            servicios_detectados=servicios_detectados,
            sistema_operativo=sistema_operativo,
            raw_output=self.output
        )

class WhoisParser(Parser):
    def parse(self) -> WhoisResult:
        dominio = None
        registrante = None
        fecha_creacion = None
        fecha_expiracion = None
        servidores_dns = []

        # Patrones para extraer información
        dominio_pattern = r"Domain Name: (.+)"
        registrante_pattern = r"Registrant Organization: (.+)"
        fecha_creacion_pattern = r"Creation Date: (.+)"
        fecha_expiracion_pattern = r"Registry Expiry Date: (.+)"
        dns_pattern = r"Name Server: (.+)"

        for line in self.output.split('\n'):
            if re.search(dominio_pattern, line):
                dominio = re.search(dominio_pattern, line).group(1)
            elif re.search(registrante_pattern, line):
                registrante = re.search(registrante_pattern, line).group(1)
            elif re.search(fecha_creacion_pattern, line):
                fecha_creacion = re.search(fecha_creacion_pattern, line).group(1)
            elif re.search(fecha_expiracion_pattern, line):
                fecha_expiracion = re.search(fecha_expiracion_pattern, line).group(1)
            elif re.search(dns_pattern, line):
                servidores_dns.append(re.search(dns_pattern, line).group(1))

        return WhoisResult(
            dominio=dominio,
            registrante=registrante,
            fecha_creacion=fecha_creacion,
            fecha_expiracion=fecha_expiracion,
            servidores_dns=servidores_dns,
            raw_output=self.output
        )

class NiktoParser(Parser):
    def parse(self) -> NiktoResult:
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

        return NiktoResult(
            vulnerabilidades=vulnerabilidades,
            advertencias=advertencias,
            informacion=informacion,
            raw_output=self.output
        )

class SSLScanParser(Parser):
    def parse(self) -> SSLScanResult:
        certificado = {}
        protocolos_soportados = []
        cifrados_soportados = []
        vulnerabilidades = []

        # Patrones para diferentes secciones
        cert_pattern = r"Subject: (.+)\nIssuer: (.+)\nNot Before: (.+)\nNot After: (.+)"
        protocol_pattern = r"Accepted\s+(\w+)\s+"
        cipher_pattern = r"(\w+)\s+(\w+)\s+(\d+)\s+(\w+)"
        vuln_pattern = r"Vulnerable to (.+)"

        # Parsear certificado
        cert_match = re.search(cert_pattern, self.output)
        if cert_match:
            certificado = {
                "subject": cert_match.group(1),
                "issuer": cert_match.group(2),
                "not_before": cert_match.group(3),
                "not_after": cert_match.group(4)
            }

        # Parsear protocolos
        for match in re.finditer(protocol_pattern, self.output):
            protocolos_soportados.append(match.group(1))

        # Parsear cifrados
        for match in re.finditer(cipher_pattern, self.output):
            cifrados_soportados.append({
                "cifrado": match.group(1),
                "tipo": match.group(2),
                "bits": match.group(3),
                "estado": match.group(4)
            })

        # Parsear vulnerabilidades
        for match in re.finditer(vuln_pattern, self.output):
            vulnerabilidades.append(match.group(1))

        return SSLScanResult(
            certificado=certificado,
            protocolos_soportados=protocolos_soportados,
            cifrados_soportados=cifrados_soportados,
            vulnerabilidades=vulnerabilidades,
            raw_output=self.output
        )

class Enum4linuxParser(Parser):
    def parse(self) -> Enum4linuxResult:
        usuarios = []
        grupos = []
        recursos_compartidos = []
        informacion_sistema = {}

        # Patrones para diferentes tipos de información
        user_pattern = r"User: (.+)"
        group_pattern = r"Group: (.+)"
        share_pattern = r"Share: (.+)"
        os_pattern = r"OS: (.+)"
        domain_pattern = r"Domain: (.+)"

        for line in self.output.split('\n'):
            if re.search(user_pattern, line):
                usuarios.append(re.search(user_pattern, line).group(1))
            elif re.search(group_pattern, line):
                grupos.append(re.search(group_pattern, line).group(1))
            elif re.search(share_pattern, line):
                recursos_compartidos.append(re.search(share_pattern, line).group(1))
            elif re.search(os_pattern, line):
                informacion_sistema["os"] = re.search(os_pattern, line).group(1)
            elif re.search(domain_pattern, line):
                informacion_sistema["domain"] = re.search(domain_pattern, line).group(1)

        return Enum4linuxResult(
            usuarios=usuarios,
            grupos=grupos,
            recursos_compartidos=recursos_compartidos,
            informacion_sistema=informacion_sistema,
            raw_output=self.output
        )

class DirbParser(Parser):
    def parse(self) -> DirbResult:
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

        return DirbResult(
            directorios_encontrados=directorios_encontrados,
            archivos_encontrados=archivos_encontrados,
            raw_output=self.output
        )

# Diccionario de parsers disponibles
PARSERS = {
    'ping': PingParser,
    'nmap': NmapParser,
    'whois': WhoisParser,
    'nikto': NiktoParser,
    'dirb': DirbParser,
    'sslscan': SSLScanParser,
    'enum4linux': Enum4linuxParser
} 