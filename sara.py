#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de escaneo de red automatizado
Autor: [Tu Nombre]
Fecha: [Fecha]
Descripción: Herramienta para realizar escaneos de red básicos usando comandos del sistema
"""

import subprocess
import sys
import argparse
import json
import yaml
from datetime import datetime
import os
from pathlib import Path
from parsers import PARSERS
from report_generator import generar_reporte_html
from tqdm import tqdm
import webbrowser

def cargar_configuracion(ruta_config='config.yml'):
    """
    Carga la configuración desde el archivo YAML.
    
    Args:
        ruta_config (str): Ruta al archivo de configuración
        
    Returns:
        dict: Configuración cargada
    """
    try:
        with open(ruta_config, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error al cargar configuración: {str(e)}")
        sys.exit(1)

def ejecutar_comando(comando, target, timeout=None):
    """
    Ejecuta un comando del sistema y retorna su salida.
    
    Args:
        comando (str): Comando a ejecutar
        target (str): IP o dominio objetivo
        timeout (int): Tiempo máximo de espera en segundos
        
    Returns:
        tuple: (éxito, salida)
    """
    try:
        comando_formateado = comando.format(target=target)
        resultado = subprocess.run(
            comando_formateado,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return True, resultado.stdout
    except subprocess.TimeoutExpired:
        return False, f"El comando excedió el tiempo máximo de {timeout} segundos"
    except Exception as e:
        return False, f"Error al ejecutar comando: {str(e)}"

def parsear_resultado(herramienta, salida, config, knowledge_base=None):
    """
    Parsea el resultado de un comando usando el parser correspondiente.
    
    Args:
        herramienta (str): Nombre de la herramienta
        salida (str): Salida del comando
        config (dict): Configuración del comando
        knowledge_base (dict): Base de conocimiento actualizada
        
    Returns:
        dict: Resultado parseado
    """
    if not config['general'].get('parse_results', True):
        return {'raw_output': salida}
        
    parser_name = config['scan_commands'][herramienta].get('parser')
    if not parser_name or parser_name not in PARSERS:
        return {'raw_output': salida}
        
    try:
        parser = PARSERS[parser_name](salida)
        resultado = parser.parse(knowledge_base=knowledge_base)
        return resultado
    except Exception as e:
        print(f"Error al parsear resultado de {herramienta}: {str(e)}")
        return {'raw_output': salida, 'error_parseo': str(e)}

def mostrar_resultados(resultados, config):
    """
    Muestra los resultados de los escaneos en la consola.
    
    Args:
        resultados (dict): Diccionario con los resultados de cada escaneo
        config (dict): Configuración cargada
    """
    print("\n" + "="*50)
    print("RESULTADOS DEL ESCANEO")
    print("="*50)
    
    for herramienta, resultado in resultados.items():
        if herramienta in config['scan_commands']:
            print(f"\n{config['scan_commands'][herramienta]['description']}:")
            print("-"*30)
            
            if isinstance(resultado, dict) and 'error' in resultado:
                print(f"Error: {resultado['error']}")
            else:
                if config['general'].get('parse_results', True):
                    # Mostrar resultados parseados
                    if isinstance(resultado, dict):
                        for campo, valor in resultado.items():
                            if campo != 'raw_output':
                                print(f"{campo}: {valor}")
                    else:
                        print(resultado.html_parse())
                    print("\nSalida completa:")
                print(resultado.get('raw_output', resultado))

def guardar_resultados(resultados, archivo_salida, formato='json'):
    """
    Guarda los resultados en un archivo.
    
    Args:
        resultados (dict): Diccionario con los resultados
        archivo_salida (str): Ruta del archivo de salida
        formato (str): Formato de salida ('json' o 'yaml')
    """
    try:
        with open(archivo_salida, 'w') as f:
            if formato.lower() == 'json':
                json.dump(resultados, f, indent=4)
            elif formato.lower() == 'yaml':
                yaml.dump(resultados, f, default_flow_style=False)
            else:
                raise ValueError(f"Formato no soportado: {formato}")
        print(f"\nResultados guardados en: {archivo_salida}")
    except Exception as e:
        print(f"Error al guardar resultados: {str(e)}")

def ejecutar_perfil(perfil, config, target, knowledge_base):
    """
    Ejecuta un perfil de escaneo específico.
    
    Args:
        perfil (str): Nombre del perfil a ejecutar
        config (dict): Configuración cargada
        target (str): IP o dominio objetivo
        knowledge_base (dict): Base de conocimiento actualizada
        
    Returns:
        dict: Resultados del perfil
    """
    resultados = {}
    herramientas_perfil = config['scan_profiles'].get(perfil, [])
    
    if not herramientas_perfil:
        print(f"Perfil '{perfil}' no encontrado en la configuración")
        return resultados
        
    print(f"\nEjecutando perfil: {perfil}")
    with tqdm(total=len(herramientas_perfil), desc="Progreso") as pbar:
        for herramienta in herramientas_perfil:
            if herramienta in config['scan_commands']:
                cmd_config = config['scan_commands'][herramienta]
                if cmd_config.get('enabled', True):
                    print(f"\nEjecutando {cmd_config['description']}...")
                    timeout = cmd_config.get('timeout', config['general']['timeout'])
                    exito, salida = ejecutar_comando(
                        cmd_config['command'],
                        target,
                        timeout=timeout
                    )
                    
                    if exito:
                        resultado_parseado = parsear_resultado(herramienta, salida, config, knowledge_base=knowledge_base)
                        resultados[herramienta] = resultado_parseado
                    else:
                        resultados[herramienta] = {'error': salida}
            pbar.update(1)
            
    return resultados

def run_searchsploit(knowledge_base):
    for port, info in knowledge_base.items():
        software = info.get('software', '')
        version = info.get('version', '')
        if software and version and version != 'No detectada':
            query = f"{software} {version}"
        else:
            query = software
        try:
            result = subprocess.run(
                ["searchsploit", query],
                capture_output=True,
                text=True
            )
            exploits = result.stdout.strip()
        except Exception as e:
            exploits = f"Error ejecutando searchsploit: {e}"
        knowledge_base[port]['searchsploit'] = exploits

def main():
    # Cargar configuración
    config = cargar_configuracion()
    knowledge_base = {}
    
    # Configuración del parser de argumentos
    parser = argparse.ArgumentParser(
        description='Herramienta de escaneo de red automatizada'
    )
    parser.add_argument(
        'target',
        help='IP o dominio a escanear'
    )
    parser.add_argument(
        '-o', '--output',
        help='Archivo para guardar los resultados (opcional)',
        default=None
    )
    parser.add_argument(
        '-p', '--profile',
        help='Perfil de escaneo (rapido, completo, web)',
        default='rapido'
    )
    parser.add_argument(
        '-c', '--command',
        help='Ejecutar un comando específico (nmap, whois, nikto, etc.)',
        default=None
    )
    parser.add_argument(
        '--html',
        help='Generar reporte HTML',
        action='store_true'
    )
    parser.add_argument(
        '--open-report',
        help='Abrir el reporte HTML automáticamente al generarlo',
        action='store_true'
    )
    parser.add_argument(
        '--searchsploit',
        help='Buscar exploits en searchsploit para cada software/versión detectado',
        action='store_true'
    )
    
    args = parser.parse_args()
    
    # Ejecutar comando específico o perfil
    if args.command:
        if args.command not in config['scan_commands']:
            print(f"Error: Comando '{args.command}' no encontrado en la configuración")
            sys.exit(1)
            
        print(f"\nEjecutando comando: {args.command}")
        cmd_config = config['scan_commands'][args.command]
        if cmd_config.get('enabled', True):
            print(f"\nEjecutando {cmd_config['description']}...")
            timeout = cmd_config.get('timeout', config['general']['timeout'])
            exito, salida = ejecutar_comando(
                cmd_config['command'],
                args.target,
                timeout=timeout
            )
            
            if exito:
                resultado_parseado = parsear_resultado(args.command, salida, config, knowledge_base=knowledge_base)
                resultados = {args.command: resultado_parseado}
            else:
                resultados = {args.command: {'error': salida}}
        else:
            print(f"Error: El comando '{args.command}' está deshabilitado en la configuración")
            sys.exit(1)
    else:
        # Ejecutar perfil seleccionado
        resultados = ejecutar_perfil(args.profile, config, args.target, knowledge_base)

    # Mostrar resultados
    mostrar_resultados(resultados, config)
    
    # Guardar resultados si se especificó archivo de salida
    if args.output:
        guardar_resultados(resultados, args.output, 'json')
    
    # Generar reporte HTML si se solicita
    if args.html:
        if getattr(args, 'searchsploit', False):
            run_searchsploit(knowledge_base)
        reporte_html = generar_reporte_html(resultados, config, args.target, args.profile, knowledge_base=knowledge_base)
        print(f"\nReporte HTML generado: {reporte_html}")
        if getattr(args, 'open_report', False):
            webbrowser.open(f'file://{os.path.abspath(reporte_html)}')

    # Guardar knowledge_base en knowledge_base.json
    with open('knowledge_base.json', 'w', encoding='utf-8') as f:
        json.dump(knowledge_base, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main() 