#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de parseo de resultados de comandos
Autor: [Tu Nombre]
Fecha: [Fecha]
Descripción: Clases para parsear los resultados de diferentes comandos de escaneo
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class PingResult:
    """Resultados parseados del comando ping"""
    paquetes_enviados: int
    paquetes_recibidos: int
    paquetes_perdidos: int
    tiempo_minimo: float
    tiempo_maximo: float
    tiempo_promedio: float
    raw_output: str

@dataclass
class NmapResult:
    """Resultados parseados del comando nmap"""
    puertos_abiertos: List[Dict[str, str]]
    servicios_detectados: List[Dict[str, str]]
    sistema_operativo: Optional[str]
    raw_output: str

@dataclass
class WhoisResult:
    """Resultados parseados del comando whois"""
    nombre_dominio: Optional[str]
    registrante: Optional[str]
    fecha_creacion: Optional[str]
    fecha_expiracion: Optional[str]
    servidores_nombre: List[str]
    raw_output: str

class ParserBase:
    """Clase base para todos los parsers"""
    def __init__(self, raw_output: str):
        self.raw_output = raw_output

class PingParser(ParserBase):
    """Parser para resultados del comando ping"""
    def parse(self) -> PingResult:
        # Patrones para extraer información del ping
        patron_paquetes = r"Paquetes: Enviados = (\d+), Recibidos = (\d+), Perdidos = (\d+)"
        patron_tiempos = r"Tiempo mínimo = (\d+)ms, Tiempo máximo = (\d+)ms, Tiempo promedio = (\d+)ms"
        
        paquetes_match = re.search(patron_paquetes, self.raw_output)
        tiempos_match = re.search(patron_tiempos, self.raw_output)
        
        if not paquetes_match or not tiempos_match:
            raise ValueError("No se pudo parsear la salida del ping")
            
        return PingResult(
            paquetes_enviados=int(paquetes_match.group(1)),
            paquetes_recibidos=int(paquetes_match.group(2)),
            paquetes_perdidos=int(paquetes_match.group(3)),
            tiempo_minimo=float(tiempos_match.group(1)),
            tiempo_maximo=float(tiempos_match.group(2)),
            tiempo_promedio=float(tiempos_match.group(3)),
            raw_output=self.raw_output
        )

class NmapParser(ParserBase):
    """Parser para resultados del comando nmap"""
    def parse(self) -> NmapResult:
        puertos_abiertos = []
        servicios_detectados = []
        sistema_operativo = None
        
        # Patrones para nmap
        patron_puerto = r"(\d+)/(tcp|udp)\s+(\w+)\s+(.*)"
        patron_os = r"OS details: (.*)"
        
        for linea in self.raw_output.split('\n'):
            puerto_match = re.search(patron_puerto, linea)
            os_match = re.search(patron_os, linea)
            
            if puerto_match:
                puerto_info = {
                    'puerto': puerto_match.group(1),
                    'protocolo': puerto_match.group(2),
                    'estado': puerto_match.group(3),
                    'servicio': puerto_match.group(4).strip()
                }
                puertos_abiertos.append(puerto_info)
                servicios_detectados.append({
                    'servicio': puerto_match.group(4).strip(),
                    'puerto': puerto_match.group(1)
                })
            elif os_match:
                sistema_operativo = os_match.group(1)
        
        return NmapResult(
            puertos_abiertos=puertos_abiertos,
            servicios_detectados=servicios_detectados,
            sistema_operativo=sistema_operativo,
            raw_output=self.raw_output
        )

class WhoisParser(ParserBase):
    """Parser para resultados del comando whois"""
    def parse(self) -> WhoisResult:
        nombre_dominio = None
        registrante = None
        fecha_creacion = None
        fecha_expiracion = None
        servidores_nombre = []
        
        # Patrones para whois
        patrones = {
            'nombre_dominio': r"Domain Name: (.*)",
            'registrante': r"Registrant Name: (.*)",
            'fecha_creacion': r"Creation Date: (.*)",
            'fecha_expiracion': r"Registry Expiry Date: (.*)",
            'servidor_nombre': r"Name Server: (.*)"
        }
        
        for linea in self.raw_output.split('\n'):
            for campo, patron in patrones.items():
                match = re.search(patron, linea, re.IGNORECASE)
                if match:
                    if campo == 'servidor_nombre':
                        servidores_nombre.append(match.group(1).strip())
                    else:
                        setattr(self, campo, match.group(1).strip())
        
        return WhoisResult(
            nombre_dominio=nombre_dominio,
            registrante=registrante,
            fecha_creacion=fecha_creacion,
            fecha_expiracion=fecha_expiracion,
            servidores_nombre=servidores_nombre,
            raw_output=self.raw_output
        )

# Diccionario de parsers disponibles
PARSERS = {
    'ping': PingParser,
    'nmap_basic': NmapParser,
    'whois': WhoisParser
} 