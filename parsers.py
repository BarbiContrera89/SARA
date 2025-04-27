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
        <div class="ping-result">
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
        puertos_html = "".join([
            f"<li>Puerto {p['puerto']}/{p['protocolo']} - {p['estado']}</li>"
            for p in self.puertos_abiertos
        ])
        
        servicios_html = "".join([
            f"<li>Puerto {s['puerto']}: {s['servicio']}</li>"
            for s in self.servicios_detectados
        ])
        
        return f"""
        <div class="nmap-result">
            <h3>Resultados de Nmap</h3>
            <h4>Puertos Abiertos:</h4>
            <ul>{puertos_html}</ul>
            <h4>Servicios Detectados:</h4>
            <ul>{servicios_html}</ul>
            {f'<h4>Sistema Operativo:</h4><p>{self.sistema_operativo}</p>' if self.sistema_operativo else ''}
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
        dns_html = "".join([f"<li>{dns}</li>" for dns in self.servidores_dns])
        
        return f"""
        <div class="whois-result">
            <h3>Resultados de Whois</h3>
            <ul>
                <li>Dominio: {self.dominio}</li>
                {f'<li>Registrante: {self.registrante}</li>' if self.registrante else ''}
                {f'<li>Fecha de creación: {self.fecha_creacion}</li>' if self.fecha_creacion else ''}
                {f'<li>Fecha de expiración: {self.fecha_expiracion}</li>' if self.fecha_expiracion else ''}
            </ul>
            <h4>Servidores DNS:</h4>
            <ul>{dns_html}</ul>
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
        vuln_html = "".join([
            f"<li>{v['tipo']}: {v['descripcion']}</li>"
            for v in self.vulnerabilidades
        ])
        
        warning_html = "".join([
            f"<li>{w['tipo']}: {w['descripcion']}</li>"
            for w in self.advertencias
        ])
        
        info_html = "".join([
            f"<li>{i['tipo']}: {i['descripcion']}</li>"
            for i in self.informacion
        ])
        
        return f"""
        <div class="nikto-result">
            <h3>Resultados de Nikto</h3>
            <h4>Vulnerabilidades:</h4>
            <ul>{vuln_html}</ul>
            <h4>Advertencias:</h4>
            <ul>{warning_html}</ul>
            <h4>Información:</h4>
            <ul>{info_html}</ul>
        </div>
        """

@dataclass
class DirbResult:
    """Resultados del escaneo Dirb"""
    directorios_encontrados: List[Dict[str, str]]
    archivos_encontrados: List[Dict[str, str]]
    raw_output: str

    def html_parse(self) -> str:
        dirs_html = "".join([
            f"<li>{d['ruta']}</li>"
            for d in self.directorios_encontrados
        ])
        
        files_html = "".join([
            f"<li>{f['ruta']}</li>"
            for f in self.archivos_encontrados
        ])
        
        return f"""
        <div class="dirb-result">
            <h3>Resultados de Dirb</h3>
            <h4>Directorios Encontrados:</h4>
            <ul>{dirs_html}</ul>
            <h4>Archivos Encontrados:</h4>
            <ul>{files_html}</ul>
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
        cert_html = "".join([
            f"<li>{k}: {v}</li>"
            for k, v in self.certificado.items()
        ])
        
        protocolos_html = "".join([
            f"<li>{p}</li>"
            for p in self.protocolos_soportados
        ])
        
        cifrados_html = "".join([
            f"<li>{c['cifrado']} ({c['tipo']}, {c['bits']} bits) - {c['estado']}</li>"
            for c in self.cifrados_soportados
        ])
        
        vuln_html = "".join([
            f"<li>{v}</li>"
            for v in self.vulnerabilidades
        ])
        
        return f"""
        <div class="sslscan-result">
            <h3>Resultados de SSLScan</h3>
            <h4>Certificado:</h4>
            <ul>{cert_html}</ul>
            <h4>Protocolos Soportados:</h4>
            <ul>{protocolos_html}</ul>
            <h4>Cifrados Soportados:</h4>
            <ul>{cifrados_html}</ul>
            <h4>Vulnerabilidades:</h4>
            <ul>{vuln_html}</ul>
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
        users_html = "".join([f"<li>{u}</li>" for u in self.usuarios])
        groups_html = "".join([f"<li>{g}</li>" for g in self.grupos])
        shares_html = "".join([f"<li>{s}</li>" for s in self.recursos_compartidos])
        
        info_html = "".join([
            f"<li>{k}: {v}</li>"
            for k, v in self.informacion_sistema.items()
        ])
        
        return f"""
        <div class="enum4linux-result">
            <h3>Resultados de Enum4linux</h3>
            <h4>Usuarios:</h4>
            <ul>{users_html}</ul>
            <h4>Grupos:</h4>
            <ul>{groups_html}</ul>
            <h4>Recursos Compartidos:</h4>
            <ul>{shares_html}</ul>
            <h4>Información del Sistema:</h4>
            <ul>{info_html}</ul>
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

        # Patrón para puertos abiertos
        puerto_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\w+)"
        for match in re.finditer(puerto_pattern, self.output):
            puertos_abiertos.append({
                "puerto": match.group(1),
                "protocolo": match.group(2),
                "estado": "open"
            })
            servicios_detectados.append({
                "puerto": match.group(1),
                "servicio": match.group(3)
            })

        # Patrón para sistema operativo
        os_pattern = r"OS details: (.+)"
        os_match = re.search(os_pattern, self.output)
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