# SARA - Sistema Automatizado de Reconocimiento y Análisis

## Descripción
SARA es una herramienta de escaneo de red automatizada que permite realizar análisis de seguridad utilizando múltiples herramientas de diagnóstico. El script está diseñado para ejecutarse en sistemas Kali Linux y proporciona una interfaz sencilla para realizar escaneos con diferentes perfiles y generar reportes detallados.

## Características Principales
- Múltiples herramientas de escaneo integradas
- Perfiles de escaneo predefinidos
- Parseo automático de resultados
- Generación de reportes HTML
- Barra de progreso en tiempo real
- Configuración flexible mediante YAML
- Manejo de errores robusto

## Requisitos
### Sistema Operativo
- Kali Linux (recomendado)
- Otras distribuciones Linux con las herramientas necesarias instaladas

### Dependencias del Sistema
```bash
# Herramientas de escaneo
sudo apt-get update
sudo apt-get install nmap whois nikto dirb sslscan enum4linux

# Dependencias de Python
pip install pyyaml tqdm jinja2
```

## Instalación
1. Clona o descarga este repositorio:
```bash
git clone [URL_DEL_REPOSITORIO]
cd sara
```

2. Instala las dependencias de Python:
```bash
pip install -r requirements.txt
```

3. Verifica que todas las herramientas estén instaladas:
```bash
python sara.py --check-tools
```

## Configuración
El archivo `config.yml` permite personalizar:
- Comandos de escaneo
- Perfiles de escaneo
- Tiempos de espera
- Formato de salida
- Campos a mostrar

### Ejemplo de Configuración
```yaml
scan_commands:
  nmap_basic:
    command: "nmap -sV -T4 {target}"
    description: "Escaneo básico de puertos"
    enabled: true

scan_profiles:
  rapido:
    - ping
    - nmap_basic
```

## Uso
### Sintaxis Básica
```bash
python sara.py <IP o dominio> [opciones]
```

### Opciones Disponibles
- `-p, --profile`: Perfil de escaneo (rapido, completo, web)
- `-o, --output`: Archivo para guardar resultados
- `-c, --config`: Ruta al archivo de configuración personalizado
- `-f, --format`: Formato de salida (json o yaml)
- `--no-parse`: Desactivar parseo de resultados
- `--html`: Generar reporte HTML
- `--check-tools`: Verificar herramientas instaladas

### Ejemplos de Uso
```bash
# Escaneo rápido básico
python sara.py 192.168.1.1

# Escaneo completo con reporte HTML
python sara.py 192.168.1.1 -p completo --html

# Escaneo web específico
python sara.py example.com -p web

# Escaneo con configuración personalizada
python sara.py 192.168.1.1 -c mi_config.yml

# Escaneo sin parseo de resultados
python sara.py 192.168.1.1 --no-parse
```

## Perfiles de Escaneo
1. **Rápido**
   - Ping
   - Nmap básico

2. **Completo**
   - Ping
   - Nmap básico
   - Whois
   - Nikto
   - SSLScan

3. **Web**
   - Nikto
   - Dirb
   - SSLScan

## Herramientas Integradas
- **Ping**: Prueba de conectividad básica
- **Nmap**: Escaneo de puertos y servicios
- **Whois**: Información de registro de dominio
- **Nikto**: Escaneo de vulnerabilidades web
- **Dirb**: Búsqueda de directorios web
- **SSLScan**: Análisis de configuración SSL/TLS

## Reportes
### Formato HTML
Los reportes HTML incluyen:
- Resumen del escaneo
- Resultados por herramienta
- Errores y advertencias
- Estadísticas del escaneo
- Timestamp de generación

### Ejemplo de Reporte
```html
Reporte de Escaneo SARA
----------------------
Objetivo: 192.168.1.1
Perfil: completo
Fecha: 2024-03-20 15:30:00

Herramientas ejecutadas: 5
Éxitos: 4
Errores: 1

[Resultados detallados por herramienta...]
```

## Estructura del Proyecto
```
.
├── sara.py            # Script principal
├── parsers.py         # Módulo de parseo
├── report_generator.py # Generador de reportes
├── config.yml         # Configuración
├── requirements.txt   # Dependencias
└── reportes/         # Directorio de reportes
```

## Personalización
### Añadir Nuevas Herramientas
1. Edita `config.yml`:
```yaml
scan_commands:
  nueva_herramienta:
    command: "comando {target}"
    description: "Descripción"
    enabled: true
    parser: "parser_name"
```

2. Crea el parser correspondiente en `parsers.py`

### Crear Nuevos Perfiles
Edita la sección `scan_profiles` en `config.yml`:
```yaml
scan_profiles:
  mi_perfil:
    - herramienta1
    - herramienta2
```

## Solución de Problemas
### Errores Comunes
1. **Herramienta no encontrada**
   - Verifica que la herramienta esté instalada
   - Usa `--check-tools` para verificar instalaciones

2. **Error de permisos**
   - Ejecuta con sudo si es necesario
   - Verifica permisos de ejecución

3. **Error de parseo**
   - Usa `--no-parse` para ver la salida cruda
   - Verifica el formato de salida de la herramienta

## Contribuciones
Las contribuciones son bienvenidas. Por favor:
1. Fork el repositorio
2. Crea una rama para tu feature
3. Envía un pull request

## Licencia
Este proyecto está bajo la licencia MIT. Ver `LICENSE` para más detalles. 