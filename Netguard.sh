##!/bin/bash

################################################################################
# NetGuardian V2.2.0 - All-in-One Edition
# Sistema Unificado de Análisis de Red con Alertas Integradas
# Todo incluido en un solo script portátil
# 
# Versión: 2.2.0 (All-in-One)
# Arquitectura: Monolítica con separación interna de funciones
################################################################################

set -euo pipefail

VERSION="2.2.0-allinone"
INTERFACE=""
DURATION=60
OUTPUT_DIR="netguardian_$(date +%Y%m%d_%H%M%S)"
FINGERPRINT_FILE=""
ANOMALIES_FILE=""
PCAP_FILE=""
TEMP_DIR=""
VERBOSE=false
DEBUG_MODE=false
DEFAULT_EMAIL="jesuscg1205@gmail.com"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Base de datos OUI expandida
declare -A OUI_DB

# Contador global de alertas
ALERT_COUNTER=0

################################################################################
# SECCIÓN 1: SISTEMA DE ALERTAS INTEGRADO
# (Funcionalidad de alert_hooks.sh integrada)
################################################################################

# Configuración de alertas (por defecto)
ENABLE_ALERT_HOOKS=true
ENABLE_DESKTOP_NOTIFY=true
ENABLE_CONSOLE_POPUP=false
ENABLE_SOUND_ALERT=true
ENABLE_WEBHOOK=false
ENABLE_SYSLOG=true
ENABLE_EMAIL_INSTANT=false
ALERT_LOG_FILE="/var/log/netguardian/alerts.log"

# URLs de Webhooks (configurables)
SLACK_WEBHOOK=""
DISCORD_WEBHOOK=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""

# Configuración de sonidos
SOUND_CRITICAL="/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"
SOUND_HIGH="/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"
SOUND_MEDIUM="/usr/share/sounds/freedesktop/stereo/message.oga"

# Cargar configuración externa si existe
HOOK_CONFIG_FILE="/etc/netguardian/alert_hooks.conf"
if [ -f "$HOOK_CONFIG_FILE" ]; then
    # Validar permisos antes de cargar
    local file_perms=$(stat -c %a "$HOOK_CONFIG_FILE" 2>/dev/null || echo "777")
    local file_owner=$(stat -c %u "$HOOK_CONFIG_FILE" 2>/dev/null || echo "999")
    
    if [ "$file_perms" -le 644 ] && { [ "$file_owner" -eq 0 ] || [ "$file_owner" -eq "$EUID" ]; }; then
        source "$HOOK_CONFIG_FILE" 2>/dev/null || true
    else
        echo "[WARNING] Archivo de configuración con permisos inseguros: $HOOK_CONFIG_FILE" >&2
    fi
fi

#-------------------------------------------------------------------------------
# Funciones de Alertas - Popup Terminal
#-------------------------------------------------------------------------------

show_terminal_popup() {
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local color="$YELLOW"
    local symbol="⚠"
    
    case "$severity" in
        CRITICAL)
            color="$RED"
            symbol="🚨"
            ;;
        HIGH)
            color="$YELLOW"
            symbol="⚠"
            ;;
        MEDIUM)
            color="$BLUE"
            symbol="ℹ"
            ;;
    esac
    
    echo ""
    echo -e "${color}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${color}║${NC}  ${symbol}  ${color}ALERT #${alert_id} - ${severity}${NC}                                        ${color}║${NC}"
    echo -e "${color}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${color}║${NC}  Rule: ${rule}${NC}"
    echo -e "${color}║${NC}  ${description}${NC}"
    echo -e "${color}║${NC}  Time: $(date +'%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${color}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Notificación de Escritorio
#-------------------------------------------------------------------------------

send_desktop_notification() {
    [ "$ENABLE_DESKTOP_NOTIFY" != true ] && return
    command -v notify-send &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local urgency="normal"
    local icon="dialog-information"
    
    case "$severity" in
        CRITICAL) urgency="critical"; icon="dialog-error" ;;
        HIGH) urgency="normal"; icon="dialog-warning" ;;
        MEDIUM) urgency="low"; icon="dialog-information" ;;
    esac
    
    local display_user=$(who | grep "(:0)" | awk '{print $1}' | head -1)
    
    if [ -n "$display_user" ]; then
        sudo -u "$display_user" DISPLAY=:0 notify-send \
            --urgency="$urgency" \
            --icon="$icon" \
            --app-name="NetGuardian" \
            "🚨 NetGuardian Alert #$alert_id" \
            "$severity: $description\n\nRule: $rule" \
            2>/dev/null &
    fi
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Popup Consola (Zenity/Dialog)
#-------------------------------------------------------------------------------

send_console_popup() {
    [ "$ENABLE_CONSOLE_POPUP" != true ] && return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    # Intentar con zenity (GUI)
    if command -v zenity &> /dev/null; then
        local display_user=$(who | grep "(:0)" | awk '{print $1}' | head -1)
        
        if [ -n "$display_user" ]; then
            local icon_type="warning"
            [ "$severity" = "CRITICAL" ] && icon_type="error"
            
            sudo -u "$display_user" DISPLAY=:0 zenity \
                --$icon_type \
                --title="NetGuardian Security Alert #$alert_id" \
                --text="<b>Severity:</b> $severity\n<b>Rule:</b> $rule\n\n$description" \
                --width=400 \
                2>/dev/null &
        fi
    # Fallback a dialog (TUI)
    elif command -v dialog &> /dev/null; then
        dialog --title "NetGuardian Alert #$alert_id" \
               --msgbox "SEVERITY: $severity\nRULE: $rule\n\n$description" \
               10 60 2>/dev/null || true
    fi
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Sonido
#-------------------------------------------------------------------------------

play_sound_alert() {
    [ "$ENABLE_SOUND_ALERT" != true ] && return
    
    local severity="$1"
    local sound_file=""
    
    case "$severity" in
        CRITICAL) sound_file="$SOUND_CRITICAL" ;;
        HIGH) sound_file="$SOUND_HIGH" ;;
        MEDIUM) sound_file="$SOUND_MEDIUM" ;;
    esac
    
    # Intentar reproducir con varios reproductores
    if command -v paplay &> /dev/null && [ -f "$sound_file" ]; then
        paplay "$sound_file" 2>/dev/null &
    elif command -v aplay &> /dev/null && [ -f "$sound_file" ]; then
        aplay "$sound_file" 2>/dev/null &
    else
        # Terminal beep según severidad
        case "$severity" in
            CRITICAL) for i in {1..3}; do echo -e "\a"; sleep 0.1; done ;;
            HIGH) for i in {1..2}; do echo -e "\a"; sleep 0.1; done ;;
            MEDIUM) echo -e "\a" ;;
        esac
    fi
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Webhook Slack
#-------------------------------------------------------------------------------

send_slack_webhook() {
    [ "$ENABLE_WEBHOOK" != true ] || [ -z "$SLACK_WEBHOOK" ] && return
    command -v curl &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    local timestamp="$5"
    
    local color="warning"
    local emoji=":warning:"
    
    case "$severity" in
        CRITICAL) color="danger"; emoji=":rotating_light:" ;;
        HIGH) color="warning"; emoji=":warning:" ;;
        MEDIUM) color="good"; emoji=":information_source:" ;;
    esac
    
    local payload=$(cat <<EOF
{
  "username": "NetGuardian",
  "icon_emoji": ":shield:",
  "attachments": [
    {
      "color": "$color",
      "title": "$emoji Alert #$alert_id - $severity",
      "text": "$description",
      "fields": [
        {
          "title": "Rule",
          "value": "$rule",
          "short": true
        },
        {
          "title": "Severity",
          "value": "$severity",
          "short": true
        },
        {
          "title": "Timestamp",
          "value": "$timestamp",
          "short": false
        }
      ],
      "footer": "NetGuardian Security System",
      "ts": $(date +%s)
    }
  ]
}
EOF
)
    
    curl -X POST -H 'Content-type: application/json' \
         --data "$payload" \
         "$SLACK_WEBHOOK" \
         2>/dev/null &
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Webhook Discord
#-------------------------------------------------------------------------------

send_discord_webhook() {
    [ "$ENABLE_WEBHOOK" != true ] || [ -z "$DISCORD_WEBHOOK" ] && return
    command -v curl &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local color_decimal=16776960  # Yellow
    
    case "$severity" in
        CRITICAL) color_decimal=16711680 ;;  # Red
        HIGH) color_decimal=16776960 ;;      # Yellow
        MEDIUM) color_decimal=3447003 ;;     # Blue
    esac
    
    local payload=$(cat <<EOF
{
  "username": "NetGuardian",
  "avatar_url": "https://i.imgur.com/4M34hi2.png",
  "embeds": [
    {
      "title": "🚨 Security Alert #$alert_id",
      "description": "$description",
      "color": $color_decimal,
      "fields": [
        {
          "name": "Severity",
          "value": "$severity",
          "inline": true
        },
        {
          "name": "Rule",
          "value": "$rule",
          "inline": true
        }
      ],
      "footer": {
        "text": "NetGuardian V$VERSION"
      },
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }
  ]
}
EOF
)
    
    curl -X POST -H 'Content-type: application/json' \
         --data "$payload" \
         "$DISCORD_WEBHOOK" \
         2>/dev/null &
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Telegram Bot
#-------------------------------------------------------------------------------

send_telegram_message() {
    [ "$ENABLE_WEBHOOK" != true ] || [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ] && return
    command -v curl &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local emoji="⚠️"
    case "$severity" in
        CRITICAL) emoji="🚨" ;;
        HIGH) emoji="⚠️" ;;
        MEDIUM) emoji="ℹ️" ;;
    esac
    
    local message="$emoji *NetGuardian Alert #$alert_id*

*Severity:* $severity
*Rule:* $rule

*Description:*
$description

_NetGuardian Security System_"
    
    curl -X POST \
         "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
         -d "chat_id=${TELEGRAM_CHAT_ID}" \
         -d "text=${message}" \
         -d "parse_mode=Markdown" \
         2>/dev/null &
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Syslog
#-------------------------------------------------------------------------------

send_syslog() {
    [ "$ENABLE_SYSLOG" != true ] && return
    command -v logger &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local priority="warning"
    case "$severity" in
        CRITICAL) priority="crit" ;;
        HIGH) priority="warning" ;;
        MEDIUM) priority="notice" ;;
    esac
    
    logger -t "netguardian[$alert_id]" -p "security.$priority" \
           "ALERT: $severity - $rule - $description" 2>/dev/null || true
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Log a Archivo
#-------------------------------------------------------------------------------

log_alert_to_file() {
    local alert_id="$1"
    local severity="$2"
    local rule="$3"
    local description="$4"
    local timestamp="$5"
    
    local log_dir=$(dirname "$ALERT_LOG_FILE")
    mkdir -p "$log_dir" 2>/dev/null || true
    
    local log_entry="[$(date +'%Y-%m-%d %H:%M:%S')] ALERT_ID=$alert_id SEVERITY=$severity RULE=$rule DESC=\"$description\" TS=$timestamp"
    
    echo "$log_entry" >> "$ALERT_LOG_FILE" 2>/dev/null || true
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Email Instantáneo
#-------------------------------------------------------------------------------

send_instant_email() {
    [ "$ENABLE_EMAIL_INSTANT" != true ] && return
    [ "$1" != "CRITICAL" ] && return  # Solo para CRITICAL
    command -v mail &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local subject="🚨 CRITICAL NetGuardian Alert #$alert_id"
    local body="NetGuardian Security Alert

Alert ID: $alert_id
Severity: $severity
Rule: $rule
Description: $description
Timestamp: $(date)

This is an automated critical alert from NetGuardian.
Please investigate immediately.

--
NetGuardian Security System"
    
    echo "$body" | mail -s "$subject" root 2>/dev/null &
}

#-------------------------------------------------------------------------------
# Función Principal: Disparar Alerta
#-------------------------------------------------------------------------------

trigger_alert_pop() {
    [ "$ENABLE_ALERT_HOOKS" != true ] && return
    
    local alert_id="$1"
    local severity="$2"
    local rule="$3"
    local description="$4"
    local timestamp="${5:-$(date +%s)}"
    
    # Popup visual en terminal
    show_terminal_popup "$severity" "$rule" "$description" "$alert_id"
    
    # Sonido de alerta
    play_sound_alert "$severity"
    
    # Notificación de escritorio
    send_desktop_notification "$severity" "$rule" "$description" "$alert_id"
    
    # Popup en consola (opcional)
    send_console_popup "$severity" "$rule" "$description" "$alert_id"
    
    # Webhooks
    send_slack_webhook "$severity" "$rule" "$description" "$alert_id" "$timestamp"
    send_discord_webhook "$severity" "$rule" "$description" "$alert_id"
    send_telegram_message "$severity" "$rule" "$description" "$alert_id"
    
    # Logs
    send_syslog "$severity" "$rule" "$description" "$alert_id"
    log_alert_to_file "$alert_id" "$severity" "$rule" "$description" "$timestamp"
    
    # Email instantáneo (solo CRITICAL)
    send_instant_email "$severity" "$rule" "$description" "$alert_id"
}

################################################################################
# SECCIÓN 2: FUNCIONES PRINCIPALES DE NETGUARDIAN
################################################################################

show_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║  ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗║
║  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
║  ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
║  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
║  ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
║  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ║
║                                                                       ║
║          Sistema Unificado de Análisis y Seguridad de Red            ║
║                     All-in-One Edition - V2.2.0                      ║
╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo ""
}

show_help() {
    show_banner
    cat << EOF
${CYAN}DESCRIPCIÓN:${NC}
    NetGuardian es un sistema unificado all-in-one que realiza:
    • Fingerprinting de dispositivos (identificación de MACs)
    • Detección de anomalías de red (ataques y comportamientos sospechosos)
    • Notificaciones en tiempo real (terminal, escritorio, webhooks)
    
    ${GREEN}✨ Versión All-in-One: Todo incluido en un solo script${NC}
    
    Genera DOS archivos JSON desde UNA SOLA captura de tráfico.

${CYAN}USO:${NC}
    $0 -i <interface> [OPTIONS]

${CYAN}OPCIONES REQUERIDAS:${NC}
    -i <interface>     Interfaz de red a monitorear

${CYAN}OPCIONES:${NC}
    -d <seconds>       Duración de captura en segundos (default: 60)
    -o <directory>     Directorio de salida (default: netguardian_TIMESTAMP)
    -v                 Modo verbose (muestra detalles del proceso)
    -n                 No-alerts mode (desactivar notificaciones pop)
    -t                 Test mode (probar sistema de alertas)
    -D                 Modo debug (diagnóstico completo del sistema)
    -h                 Mostrar esta ayuda
    -l                 Listar interfaces disponibles
    -V                 Mostrar versión

${CYAN}EJEMPLOS:${NC}
    # Análisis básico de 60 segundos
    sudo $0 -i eth0

    # Análisis extendido de 5 minutos con modo verbose
    sudo $0 -i wlan0 -d 300 -v

    # Probar sistema de alertas
    $0 -t

    # Diagnóstico del sistema
    $0 -D

${CYAN}CONFIGURACIÓN DE WEBHOOKS:${NC}
    Crea el archivo: /etc/netguardian/alert_hooks.conf
    
    Contenido ejemplo:
        ENABLE_WEBHOOK=true
        SLACK_WEBHOOK="https://hooks.slack.com/services/..."
        DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
        TELEGRAM_BOT_TOKEN="123456789:ABC..."
        TELEGRAM_CHAT_ID="123456789"

${CYAN}SALIDAS:${NC}
    El sistema genera un directorio con 3 archivos:
    
    📁 netguardian_YYYYMMDD_HHMMSS/
       ├── 📄 fingerprint.json      → Inventario de dispositivos
       ├── 📄 anomalies.json        → Alertas de seguridad
       └── 📄 capture.pcap          → Captura de tráfico raw

${CYAN}TIPOS DE ANOMALÍAS DETECTADAS:${NC}
    • MAC Spoofing       → Suplantación de direcciones MAC
    • DHCP Conflicts     → Conflictos en asignación de IPs
    • MAC Changer        → Cambios frecuentes de MAC
    • ARP Spoofing       → Envenenamiento de caché ARP

${CYAN}REQUISITOS:${NC}
    • tshark (Wireshark CLI)
    • jq (opcional, para formato JSON)
    • Permisos de root o grupo wireshark
    • curl (opcional, para webhooks)
    • notify-send (opcional, para notificaciones de escritorio)
EOF
}

list_interfaces() {
    show_banner
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Interfaces de red disponibles:${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    if command -v ip &> /dev/null; then
        echo -e "${BLUE}Estado de interfaces:${NC}"
        ip -br link show | while read -r iface status rest; do
            if [[ "$status" == "UP" ]]; then
                echo -e "  ${GREEN}●${NC} $iface ${GREEN}(UP)${NC}"
            elif [[ "$status" == "DOWN" ]]; then
                echo -e "  ${RED}○${NC} $iface ${RED}(DOWN)${NC}"
            else
                echo -e "  ${YELLOW}○${NC} $iface ${YELLOW}($status)${NC}"
            fi
        done
    else
        tshark -D 2>/dev/null | sed 's/^/  /'
    fi
    echo ""
}

################################################################################
# FUNCIONES DE LOGGING
################################################################################

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $*"
}

log_verbose() {
    [[ "$VERBOSE" == true ]] && echo -e "${BLUE}[VERBOSE]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

log_error() {
    echo -e "${RED}[✗]${NC} $*" >&2
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $*"
}

################################################################################
# FUNCIONES DE VALIDACIÓN
################################################################################

check_dependencies() {
    log "Verificando dependencias..."
    
    local deps=("tshark" "awk" "timeout")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Dependencias faltantes: ${missing[*]}"
        echo ""
        echo -e "${YELLOW}Instalar en Debian/Ubuntu:${NC}"
        echo "  sudo apt install tshark coreutils"
        echo ""
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_warning "jq no está instalado (opcional, pero recomendado)"
        log_warning "Instalar con: sudo apt install jq"
    fi
    
    log_success "Todas las dependencias están instaladas"
}

check_permissions() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Este script requiere permisos de root"
        echo ""
        echo "Ejecuta con: sudo $0 $*"
        echo ""
        exit 1
    fi
}

################################################################################
# BASE DE DATOS OUI
################################################################################

load_oui_database() {
    OUI_DB=(
        # Virtualización
        ["00:50:56"]="VMware"
        ["00:0C:29"]="VMware"
        ["00:05:69"]="VMware"
        ["08:00:27"]="VirtualBox"
        ["52:54:00"]="QEMU/KVM"
        ["00:15:5D"]="Microsoft Hyper-V"
        ["00:1C:42"]="Parallels"
        
        # Raspberry Pi & IoT Boards
        ["B8:27:EB"]="Raspberry Pi"
        ["DC:A6:32"]="Raspberry Pi"
        ["E4:5F:01"]="Raspberry Pi"
        ["28:CD:C1"]="Raspberry Pi"
        
        # Apple
        ["AC:DE:48"]="Apple"
        ["F0:18:98"]="Apple"
        ["D8:9E:3F"]="Apple"
        ["3C:22:FB"]="Apple"
        ["A4:5E:60"]="Apple"
        ["00:1C:B3"]="Apple"
        ["00:23:DF"]="Apple"
        
        # Routers & Networking
        ["DC:CE:C1"]="TP-Link"
        ["50:C7:BF"]="TP-Link"
        ["A4:2B:B0"]="TP-Link"
        ["00:1D:0F"]="Cisco"
        ["00:0A:42"]="Cisco"
        ["A0:63:91"]="Netgear"
        ["E0:91:F5"]="Netgear"
        ["00:1B:2F"]="D-Link"
        ["14:D6:4D"]="D-Link"
        ["00:0B:86"]="Arris"
        
        # Intel/PC
        ["A4:2B:B0"]="Intel"
        ["00:1B:77"]="Intel"
        ["D8:9E:F3"]="Intel"
        ["94:C6:91"]="Intel"
        
        # Móviles - Samsung
        ["00:12:FB"]="Samsung"
        ["5C:0A:5B"]="Samsung"
        ["E8:50:8B"]="Samsung"
        ["CC:3A:61"]="Samsung"
        
        # Móviles - Xiaomi
        ["44:07:0B"]="Xiaomi"
        ["34:CE:00"]="Xiaomi"
        ["F8:C4:F3"]="Xiaomi"
        ["64:09:80"]="Xiaomi"
        
        # Móviles - Huawei
        ["00:18:82"]="Huawei"
        ["F0:79:59"]="Huawei"
        ["78:F5:FD"]="Huawei"
        
        # Móviles - Otros
        ["D4:6E:0E"]="Motorola"
        ["00:26:BA"]="Motorola"
        ["10:68:3F"]="LG"
        ["00:E0:91"]="LG"
        
        # IoT - ESP32/ESP8266
        ["EC:FA:BC"]="Espressif"
        ["24:0A:C4"]="Espressif"
        ["30:AE:A4"]="Espressif"
        ["A4:CF:12"]="Espressif"
        
        # IoT - Otros
        ["68:C6:3A"]="Tuya"
        ["10:D5:61"]="Sonoff"
        ["84:F3:EB"]="Shelly"
        
        # Google
        ["98:FA:9B"]="Google"
        ["DA:A1:19"]="Google"
        ["F4:F5:D8"]="Google"
        
        # Microsoft
        ["00:50:F2"]="Microsoft"
        
        # Printers
        ["00:1E:C2"]="HP"
        ["00:21:5A"]="HP"
        ["00:1B:A9"]="Canon"
        ["00:00:48"]="Epson"
        ["00:80:77"]="Brother"
        
        # Gaming
        ["7C:ED:8D"]="Sony PlayStation"
        ["FC:0F:E6"]="Sony PlayStation"
        ["00:1F:EA"]="Microsoft Xbox"
        ["00:50:F2"]="Microsoft Xbox"
        ["00:17:AB"]="Nintendo"
        
        # TV/Streaming
        ["00:04:4B"]="Roku"
        ["B8:9A:2A"]="Roku"
        ["E4:F0:42"]="Amazon"
    )
}

get_vendor() {
    local mac="$1"
    local oui="${mac:0:8}"
    oui=$(echo "$oui" | tr 'a-z' 'A-Z')
    
    if [[ -n "${OUI_DB[$oui]:-}" ]]; then
        echo "${OUI_DB[$oui]}"
    else
        echo "Unknown"
    fi
}

estimate_device_type() {
    local mac="$1"
    local vendor="$2"
    local protocols="$3"
    local packets="$4"
    
    # Clasificación por vendor (más confiable)
    case "$vendor" in
        *"TP-Link"*|*"Cisco"*|*"Netgear"*|*"D-Link"*|*"Arris"*)
            echo "Router/Gateway"
            return
            ;;
        *"Apple"*)
            if [[ "$mac" == "f0:18:98"* ]]; then
                echo "Mobile Device"
            else
                echo "PC/Workstation"
            fi
            return
            ;;
        *"Raspberry Pi"*)
            if [[ "$packets" -gt 1000 ]]; then
                echo "Server/IoT Hub"
            else
                echo "IoT Device"
            fi
            return
            ;;
        *"Xiaomi"*|*"Tuya"*|*"Espressif"*|*"Sonoff"*|*"Shelly"*)
            echo "IoT Device"
            return
            ;;
        *"Samsung"*|*"Huawei"*|*"Motorola"*|*"LG"*)
            echo "Mobile Device"
            return
            ;;
        *"HP"*|*"Canon"*|*"Epson"*|*"Brother"*)
            echo "Printer"
            return
            ;;
        *"Sony"*|*"Roku"*|*"Amazon"*)
            echo "Smart TV/Streaming"
            return
            ;;
        *"Xbox"*|*"PlayStation"*|*"Nintendo"*)
            echo "Gaming Console"
            return
            ;;
        *"VMware"*|*"VirtualBox"*|*"QEMU"*|*"Hyper-V"*|*"Parallels"*)
            echo "Virtual Machine"
            return
            ;;
        *"Google"*)
            echo "Smart Speaker/Chromecast"
            return
            ;;
    esac
    
    # Clasificación por protocolos
    if [[ "$protocols" == *"IGMP"* ]] || [[ "$protocols" == *"STP"* ]]; then
        echo "Router/Gateway"
    elif [[ "$protocols" == *"MQTT"* ]] || [[ "$protocols" == *"CoAP"* ]]; then
        echo "IoT Device"
    elif [[ "$protocols" == *"QUIC"* ]]; then
        echo "Mobile Device"
    elif [[ "$protocols" == *"IPP"* ]]; then
        echo "Printer"
    elif [[ "$protocols" == *"SSH"* ]] && [[ "$packets" -gt 500 ]]; then
        echo "Server"
    elif [[ "$protocols" == *"SMB"* ]] || [[ "$protocols" == *"SMB2"* ]]; then
        echo "PC/Workstation"
    elif [[ "$protocols" == *"RDP"* ]]; then
        echo "Windows PC"
    elif [[ "$protocols" == *"HTTP"* ]] || [[ "$protocols" == *"TLS"* ]]; then
        if [[ "$packets" -lt 300 ]]; then
            echo "Mobile Device"
        else
            echo "PC/Workstation"
        fi
    else
        echo "Unknown"
    fi
}

################################################################################
# CAPTURA DE TRÁFICO
################################################################################

create_output_structure() {
    log "Creando estructura de directorios..."
    
    mkdir -p "$OUTPUT_DIR"
    TEMP_DIR="$OUTPUT_DIR/.tmp"
    mkdir -p "$TEMP_DIR"/{capture,fingerprint,anomalies}
    
    PCAP_FILE="$OUTPUT_DIR/capture.pcap"
    FINGERPRINT_FILE="$OUTPUT_DIR/fingerprint.json"
    ANOMALIES_FILE="$OUTPUT_DIR/anomalies.json"
    
    log_verbose "Directorio de salida: $OUTPUT_DIR"
    log_verbose "Archivo PCAP: $PCAP_FILE"
}

capture_traffic() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    log_success "Iniciando captura de tráfico unificada"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BLUE}Interfaz:${NC}  $INTERFACE"
    echo -e "  ${BLUE}Duración:${NC}  ${DURATION}s"
    echo -e "  ${BLUE}Filtro:${NC}    Tráfico completo (fingerprint + anomalías)"
    echo ""
    
    log "Capturando tráfico..."
    
    # Captura sin filtro para obtener TODO el tráfico
    timeout "$((DURATION + 5))" tshark -i "$INTERFACE" \
        -w "$PCAP_FILE" \
        -a duration:"$DURATION" \
        2>/dev/null &
    
    local tshark_pid=$!
    
    # Barra de progreso
    for ((i=1; i<=DURATION; i++)); do
        printf "\r  ${YELLOW}Progreso:${NC} ["
        local filled=$((i * 50 / DURATION))
        for ((j=0; j<50; j++)); do
            [ $j -lt $filled ] && printf "█" || printf "░"
        done
        printf "] %3d%%" $((i * 100 / DURATION))
        sleep 1
    done
    echo -e "\n"
    
    wait $tshark_pid 2>/dev/null
    
    if [ ! -f "$PCAP_FILE" ] || [ ! -s "$PCAP_FILE" ]; then
        log_error "Error en la captura de tráfico"
        cleanup
        exit 1
    fi
    
    local pcap_size=$(du -h "$PCAP_FILE" | cut -f1)
    local packet_count=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l)
    
    log_success "Captura completada: $packet_count paquetes ($pcap_size)"
}

################################################################################
# ANÁLISIS: FINGERPRINTING
################################################################################

analyze_fingerprinting() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    log_success "Analizando huellas digitales de dispositivos"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    log "Extrayendo direcciones MAC únicas..."
    tshark -r "$PCAP_FILE" -T fields -e eth.src 2>/dev/null | \
        grep -v "^$" | sort -u > "$TEMP_DIR/fingerprint/macs.txt"
    
    local mac_count=$(wc -l < "$TEMP_DIR/fingerprint/macs.txt")
    log_success "Encontrados $mac_count dispositivos únicos"
    
    log "Procesando información de cada dispositivo..."
    
    local devices_json="["
    local first=true
    local processed=0
    
    while IFS= read -r mac; do
        [[ -z "$mac" ]] && continue
        
        processed=$((processed + 1))
        
        if [[ "$VERBOSE" == true ]]; then
            printf "\r  Procesando dispositivo %d/%d" "$processed" "$mac_count"
        fi
        
        # Estadísticas por MAC
        local stats=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" 2>/dev/null | wc -l)
        [[ $stats -eq 0 ]] && continue
        
        # Bytes totales
        local bytes=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields -e frame.len 2>/dev/null | \
            awk '{sum+=$1} END {print sum+0}')
        
        # Protocolos (top 10)
        local protocols=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields \
            -e _ws.col.Protocol 2>/dev/null | sort | uniq -c | sort -rn | head -10 | \
            awk '{printf "\"%s\":%d,", $2, $1}' | sed 's/,$//')
        
        # Direcciones IPv4
        local ipv4=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields \
            -e ip.src 2>/dev/null | grep -v "^$" | sort -u | \
            awk '{printf "\"%s\",", $0}' | sed 's/,$//')
        
        # Direcciones IPv6
        local ipv6=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields \
            -e ipv6.src 2>/dev/null | grep -v "^$" | sort -u | head -3 | \
            awk '{printf "\"%s\",", $0}' | sed 's/,$//')
        
        # Timestamps
        local first_seen=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields \
            -e frame.time 2>/dev/null | head -1)
        local last_seen=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields \
            -e frame.time 2>/dev/null | tail -1)
        
        # Vendor y tipo de dispositivo
        local vendor=$(get_vendor "$mac")
        local device_type=$(estimate_device_type "$mac" "$vendor" "$protocols" "$stats")
        
        # Calcular throughput promedio
        local avg_packet_size=0
        if [[ $stats -gt 0 ]]; then
            avg_packet_size=$((bytes / stats))
        fi
        
        # Construir JSON del dispositivo
        local device_json=$(cat <<EOF
{
  "mac_address": "$mac",
  "vendor": "$vendor",
  "estimated_type": "$device_type",
  "statistics": {
    "total_packets": $stats,
    "total_bytes": $bytes,
    "avg_packet_size": $avg_packet_size
  },
  "protocols": {$protocols},
  "ip_addresses": {
    "ipv4": [$ipv4],
    "ipv6": [$ipv6]
  },
  "activity": {
    "first_seen": "$first_seen",
    "last_seen": "$last_seen"
  }
}
EOF
)
        
        if $first; then
            devices_json+="$device_json"
            first=false
        else
            devices_json+=",$device_json"
        fi
        
    done < "$TEMP_DIR/fingerprint/macs.txt"
    
    [[ "$VERBOSE" == true ]] && echo ""
    
    devices_json+="]"
    
    # Crear JSON final
    local final_json=$(cat <<EOF
{
  "scan_info": {
    "tool": "NetGuardian",
    "version": "$VERSION",
    "interface": "$INTERFACE",
    "duration": $DURATION,
    "timestamp": "$(date -Iseconds)",
    "pcap_file": "$(basename "$PCAP_FILE")"
  },
  "summary": {
    "total_devices": $mac_count,
    "total_packets_analyzed": $(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l)
  },
  "devices": $devices_json
}
EOF
)
    
    echo "$final_json" | jq '.' > "$FINGERPRINT_FILE" 2>/dev/null || {
        echo "$final_json" > "$FINGERPRINT_FILE"
    }
    
    log_success "Fingerprinting completado: $FINGERPRINT_FILE"
}

################################################################################
# ANÁLISIS: DETECCIÓN DE ANOMALÍAS
################################################################################

increment_alert() {
    ALERT_COUNTER=$((ALERT_COUNTER + 1))
}

# Función para procesar alertas del JSON y disparar popups en tiempo real
process_and_trigger_alerts() {
    local json_file="$1"
    
    # Si no existen alertas o el archivo está vacío, salir
    if [ ! -f "$json_file" ] || [ ! -s "$json_file" ]; then
        return
    fi
    
    # Intentar parsear con jq si está disponible
    if command -v jq &> /dev/null; then
        local alerts_count=$(jq 'length' "$json_file" 2>/dev/null || echo 0)
        
        if [ "$alerts_count" -gt 0 ]; then
            # Procesar cada alerta
            for i in $(seq 0 $((alerts_count - 1))); do
                local alert_id=$(jq -r ".[$i].alert_id // 0" "$json_file" 2>/dev/null)
                local severity=$(jq -r ".[$i].severity // \"UNKNOWN\"" "$json_file" 2>/dev/null)
                local rule=$(jq -r ".[$i].rule // \"UNKNOWN\"" "$json_file" 2>/dev/null)
                local description=$(jq -r ".[$i].description // \"No description\"" "$json_file" 2>/dev/null)
                local timestamp=$(jq -r ".[$i].timestamp // \"N/A\"" "$json_file" 2>/dev/null)
                
                # Disparar alerta pop
                if [ "$alert_id" != "0" ] && [ "$alert_id" != "null" ]; then
                    trigger_alert_pop "$alert_id" "$severity" "$rule" "$description" "$timestamp"
                fi
            done
        fi
    fi
}

analyze_mac_spoofing() {
    log_verbose "Detectando MAC Spoofing..."
    
    tshark -r "$PCAP_FILE" -Y "arp" -T fields \
        -e frame.time_epoch -e eth.src -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 \
        -E separator=, 2>/dev/null > "$TEMP_DIR/anomalies/arp_data.csv"
    
    if [ ! -s "$TEMP_DIR/anomalies/arp_data.csv" ]; then
        echo "[]" > "$TEMP_DIR/anomalies/mac_spoofing.json"
        return
    fi
    
    awk -F, -v counter="$ALERT_COUNTER" 'BEGIN{print"[";f=1;id=counter}{mac=$2;ip=$3;t=$1;if(mac==""||ip=="")next;if(mac in m){if(m[mac]!=ip){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"MAC_SPOOFING_R2\",\"description\":\"Same MAC address with multiple IP addresses\",\"severity\":\"HIGH\",\"details\":{\"mac_address\":\"%s\",\"ip_addresses\":[\"%s\",\"%s\"]},\"protocol\":\"ARP\",\"timestamp\":\"%s\"}\n",id,mac,m[mac],ip,t}}m[mac]=ip;if(ip in im&&im[ip]!=mac){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"MAC_SPOOFING_R3\",\"description\":\"Multiple MAC addresses for same IP\",\"severity\":\"CRITICAL\",\"details\":{\"ip_address\":\"%s\",\"mac_addresses\":[\"%s\",\"%s\"]},\"protocol\":\"ARP\",\"timestamp\":\"%s\"}\n",id,ip,im[ip],mac,t}im[ip]=mac}END{print"]";print id > "/tmp/alert_counter.tmp"}' "$TEMP_DIR/anomalies/arp_data.csv" > "$TEMP_DIR/anomalies/mac_spoofing.json"
    
    if [ -f /tmp/alert_counter.tmp ]; then
        ALERT_COUNTER=$(cat /tmp/alert_counter.tmp)
        rm -f /tmp/alert_counter.tmp
    fi
    
    process_and_trigger_alerts "$TEMP_DIR/anomalies/mac_spoofing.json"
}

analyze_dhcp_conflicts() {
    log_verbose "Detectando conflictos DHCP..."
    
    tshark -r "$PCAP_FILE" -Y "dhcp or bootp" -T fields \
        -e frame.time_epoch -e eth.src -e dhcp.option.dhcp \
        -e dhcp.option.requested_ip_address -e dhcp.ip.your \
        -E separator=, 2>/dev/null > "$TEMP_DIR/anomalies/dhcp_data.csv"
    
    if [ ! -s "$TEMP_DIR/anomalies/dhcp_data.csv" ]; then
        echo "[]" > "$TEMP_DIR/anomalies/dhcp_conflicts.json"
        return
    fi
    
    awk -F, -v counter="$ALERT_COUNTER" 'BEGIN{print"[";f=1;n=0;id=counter}{t=$1;mac=$2;mt=$3;rip=$4;yip=$5;if(t=="")next;if(mt=="6"){n++;lt=t}if(yip!=""&&yip in ia){if(ia[yip]!=mac){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"DHCP_CONFLICT_R1\",\"description\":\"Duplicate IP assignment detected\",\"severity\":\"HIGH\",\"details\":{\"ip_address\":\"%s\",\"mac_addresses\":[\"%s\",\"%s\"]},\"protocol\":\"DHCP\",\"timestamp\":\"%s\"}\n",id,yip,ia[yip],mac,t}}if(yip!="")ia[yip]=mac}END{if(n>5){id++;if(!f)print",";printf"  {\"alert_id\":%d,\"rule\":\"DHCP_CONFLICT_R2\",\"description\":\"DHCP NAK spike detected\",\"severity\":\"MEDIUM\",\"details\":{\"nak_count\":%d},\"protocol\":\"DHCP\",\"timestamp\":\"%s\"}\n",id,n,lt}print"]";print id > "/tmp/alert_counter.tmp"}' "$TEMP_DIR/anomalies/dhcp_data.csv" > "$TEMP_DIR/anomalies/dhcp_conflicts.json"
    
    if [ -f /tmp/alert_counter.tmp ]; then
        ALERT_COUNTER=$(cat /tmp/alert_counter.tmp)
        rm -f /tmp/alert_counter.tmp
    fi
    
    process_and_trigger_alerts "$TEMP_DIR/anomalies/dhcp_conflicts.json"
}

analyze_mac_changer() {
    log_verbose "Detectando cambios de MAC..."
    
    tshark -r "$PCAP_FILE" -Y "arp" -T fields \
        -e frame.time_epoch -e arp.src.proto_ipv4 -e arp.src.hw_mac \
        -E separator=, 2>/dev/null | sort -t, -k2 > "$TEMP_DIR/anomalies/mac_changes.csv"
    
    if [ ! -s "$TEMP_DIR/anomalies/mac_changes.csv" ]; then
        echo "[]" > "$TEMP_DIR/anomalies/mac_changer.json"
        return
    fi
    
    awk -F, -v counter="$ALERT_COUNTER" 'BEGIN{print"[";f=1;id=counter}{t=$1;ip=$2;mac=$3;if(ip==""||mac=="")next;if(ip in im){if(im[ip]!=mac){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"MAC_CHANGER_R1\",\"description\":\"Same IP with different MAC address\",\"severity\":\"MEDIUM\",\"details\":{\"ip_address\":\"%s\",\"old_mac\":\"%s\",\"new_mac\":\"%s\"},\"protocol\":\"ARP\",\"timestamp\":\"%s\"}\n",id,ip,im[ip],mac,t;cc[ip]++}}im[ip]=mac}END{for(ip in cc){if(cc[ip]>=3){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"MAC_CHANGER_R3\",\"description\":\"Frequent MAC changes detected\",\"severity\":\"HIGH\",\"details\":{\"ip_address\":\"%s\",\"change_count\":%d},\"protocol\":\"ARP\",\"timestamp\":\"N/A\"}\n",id,ip,cc[ip]}}print"]";print id > "/tmp/alert_counter.tmp"}' "$TEMP_DIR/anomalies/mac_changes.csv" > "$TEMP_DIR/anomalies/mac_changer.json"
    
    if [ -f /tmp/alert_counter.tmp ]; then
        ALERT_COUNTER=$(cat /tmp/alert_counter.tmp)
        rm -f /tmp/alert_counter.tmp
    fi
    
    process_and_trigger_alerts "$TEMP_DIR/anomalies/mac_changer.json"
}

analyze_arp_spoofing() {
    log_verbose "Detectando ARP Spoofing..."
    
    tshark -r "$PCAP_FILE" -Y "arp.opcode == 2" -T fields \
        -e frame.time_epoch -e eth.src -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 \
        -E separator=, 2>/dev/null > "$TEMP_DIR/anomalies/arp_replies.csv"
    
    if [ ! -s "$TEMP_DIR/anomalies/arp_replies.csv" ]; then
        echo "[]" > "$TEMP_DIR/anomalies/arp_spoofing.json"
        return
    fi
    
    awk -F, -v counter="$ALERT_COUNTER" 'BEGIN{print"[";f=1;id=counter}{t=$1;mac=$2;sip=$3;dip=$4;if(mac==""||sip=="")next;k=sip;if(k in imh){if(imh[k]!=mac){ic[k]++;if(ic[k]>3){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"ARP_SPOOFING_R2\",\"description\":\"ARP cache instability detected\",\"severity\":\"HIGH\",\"details\":{\"ip_address\":\"%s\",\"mac_changes\":%d,\"current_mac\":\"%s\"},\"protocol\":\"ARP\",\"timestamp\":\"%s\"}\n",id,sip,ic[k],mac,t}}}imh[k]=mac;mr[mac]++}END{for(mac in mr){if(mr[mac]>50){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"ARP_SPOOFING_R3\",\"description\":\"Excessive ARP replies from single MAC\",\"severity\":\"CRITICAL\",\"details\":{\"mac_address\":\"%s\",\"reply_count\":%d},\"protocol\":\"ARP\",\"timestamp\":\"N/A\"}\n",id,mac,mr[mac]}}print"]";print id > "/tmp/alert_counter.tmp"}' "$TEMP_DIR/anomalies/arp_replies.csv" > "$TEMP_DIR/anomalies/arp_spoofing.json"
    
    if [ -f /tmp/alert_counter.tmp ]; then
        ALERT_COUNTER=$(cat /tmp/alert_counter.tmp)
        rm -f /tmp/alert_counter.tmp
    fi
    
    process_and_trigger_alerts "$TEMP_DIR/anomalies/arp_spoofing.json"
}

analyze_anomalies() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    log_success "Detectando anomalías de seguridad"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    ALERT_COUNTER=0
    
    analyze_mac_spoofing
    analyze_dhcp_conflicts
    analyze_mac_changer
    analyze_arp_spoofing
    
    # Combinar todas las alertas
    log "Consolidando alertas..."
    
    local all_alerts="["
    local first=true
    
    for alert_file in "$TEMP_DIR/anomalies/"*.json; do
        if [ -f "$alert_file" ] && [ -s "$alert_file" ]; then
            local content=$(jq -c '.[]' "$alert_file" 2>/dev/null || true)
            if [ -n "$content" ]; then
                while IFS= read -r line; do
                    if $first; then
                        all_alerts+="$line"
                        first=false
                    else
                        all_alerts+=",$line"
                    fi
                done <<< "$content"
            fi
        fi
    done
    
    all_alerts+="]"
    
    # Contar por severidad
    local critical=0
    local high=0
    local medium=0
    
    if command -v jq &> /dev/null; then
        critical=$(echo "$all_alerts" | jq '[.[] | select(.severity=="CRITICAL")] | length' 2>/dev/null || echo 0)
        high=$(echo "$all_alerts" | jq '[.[] | select(.severity=="HIGH")] | length' 2>/dev/null || echo 0)
        medium=$(echo "$all_alerts" | jq '[.[] | select(.severity=="MEDIUM")] | length' 2>/dev/null || echo 0)
    fi
    
    # JSON final
    local final_json=$(cat <<EOF
{
  "scan_info": {
    "tool": "NetGuardian",
    "version": "$VERSION",
    "interface": "$INTERFACE",
    "duration": $DURATION,
    "timestamp": "$(date -Iseconds)",
    "pcap_file": "$(basename "$PCAP_FILE")"
  },
  "summary": {
    "total_alerts": $ALERT_COUNTER,
    "by_severity": {
      "critical": $critical,
      "high": $high,
      "medium": $medium
    }
  },
  "alerts": $all_alerts
}
EOF
)
    
    echo "$final_json" | jq '.' > "$ANOMALIES_FILE" 2>/dev/null || {
        echo "$final_json" > "$ANOMALIES_FILE"
    }
    
    log_success "Análisis de anomalías completado: $ANOMALIES_FILE"
}

################################################################################
# RESUMEN FINAL
################################################################################

display_final_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}NETGUARDIAN - ANÁLISIS COMPLETADO${NC}                         ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Información general
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Información del análisis:${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "   ${BLUE}●${NC} Interfaz:         $INTERFACE"
    echo -e "   ${BLUE}●${NC} Duración:         ${DURATION}s"
    echo -e "   ${BLUE}●${NC} Timestamp:        $(date)"
    echo -e "   ${BLUE}●${NC} Directorio:       $OUTPUT_DIR"
    echo ""
    
    # Fingerprinting
    if [ -f "$FINGERPRINT_FILE" ] && command -v jq &> /dev/null; then
        local total_devices=$(jq '.summary.total_devices' "$FINGERPRINT_FILE" 2>/dev/null || echo 0)
        local total_packets=$(jq '.summary.total_packets_analyzed' "$FINGERPRINT_FILE" 2>/dev/null || echo 0)
        
        echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
        echo -e "${BLUE}Fingerprinting de dispositivos:${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
        echo -e "   ${GREEN}✓${NC} Dispositivos detectados:  $total_devices"
        echo -e "   ${GREEN}✓${NC} Paquetes analizados:      $total_packets"
        echo ""
    fi
    
    # Anomalías
    if [ -f "$ANOMALIES_FILE" ] && command -v jq &> /dev/null; then
        local total_alerts=$(jq '.summary.total_alerts' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        local critical=$(jq '.summary.by_severity.critical' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        local high=$(jq '.summary.by_severity.high' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        local medium=$(jq '.summary.by_severity.medium' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        
        echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
        echo -e "${BLUE}Detección de anomalías:${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
        echo -e "   ${BLUE}Total de alertas:${NC}     $total_alerts"
        
        if [ "$critical" -gt 0 ]; then
            echo -e "   ${RED}●${NC} Críticas:            ${RED}$critical${NC}"
        fi
        if [ "$high" -gt 0 ]; then
            echo -e "   ${YELLOW}●${NC} Altas:               ${YELLOW}$high${NC}"
        fi
        if [ "$medium" -gt 0 ]; then
            echo -e "   ${BLUE}●${NC} Medias:              ${BLUE}$medium${NC}"
        fi
        
        if [ "$total_alerts" -eq 0 ]; then
            echo -e "   ${GREEN}✓${NC} No se detectaron amenazas"
        fi
        echo ""
    fi
    
    # Archivos generados
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Archivos generados:${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "   ${BLUE}●${NC} fingerprint.json  → Inventario de dispositivos"
    echo -e "   ${BLUE}●${NC} anomalies.json    → Reporte de seguridad"
    echo -e "   ${BLUE}●${NC} capture.pcap      → Captura raw de tráfico"
    echo ""
    
    # Recomendaciones
    if [ -f "$ANOMALIES_FILE" ] && command -v jq &> /dev/null; then
        local total_alerts=$(jq '.summary.total_alerts' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        local critical=$(jq '.summary.by_severity.critical' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        
        if [ "$critical" -gt 0 ]; then
            echo -e "${RED}⚠️  ATENCIÓN:${NC} Se detectaron ${RED}$critical alertas CRÍTICAS${NC}"
            echo -e "    Revisa inmediatamente el archivo: ${YELLOW}$ANOMALIES_FILE${NC}"
            echo ""
        elif [ "$total_alerts" -gt 0 ]; then
            echo -e "${YELLOW}ℹ️  INFO:${NC} Se detectaron $total_alerts anomalías"
            echo -e "    Revisa el archivo: ${YELLOW}$ANOMALIES_FILE${NC}"
            echo ""
        fi
    fi
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

################################################################################
# LIMPIEZA
################################################################################

cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        log_verbose "Limpiando archivos temporales..."
        rm -rf "$TEMP_DIR"
    fi
    
    rm -f /tmp/alert_counter.tmp
}

################################################################################
# MODO TEST
################################################################################

test_alert_system() {
    show_banner
    echo "Testing NetGuardian Alert System..."
    echo ""
    
    echo "Testing MEDIUM alert..."
    trigger_alert_pop 999 "MEDIUM" "TEST_RULE" "This is a test medium alert" "$(date +%s)"
    sleep 2
    
    echo "Testing HIGH alert..."
    trigger_alert_pop 998 "HIGH" "TEST_RULE" "This is a test high alert" "$(date +%s)"
    sleep 2
    
    echo "Testing CRITICAL alert..."
    trigger_alert_pop 997 "CRITICAL" "TEST_RULE" "This is a test critical alert" "$(date +%s)"
    
    echo ""
    echo "Alert system test completed!"
    echo ""
    exit 0
}

################################################################################
# MODO DEBUG
################################################################################

debug_system() {
    show_banner
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}DIAGNÓSTICO COMPLETO DEL SISTEMA${NC}                         ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    local all_passed=true
    
    # 1. Sistema
    echo -e "${BLUE}[1/8]${NC} ${CYAN}Información del Sistema${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  ${GREEN}✓${NC} Sistema: $(uname -s) $(uname -r)"
    echo -e "  ${GREEN}✓${NC} Arquitectura: $(uname -m)"
    [ -f /etc/os-release ] && source /etc/os-release && echo -e "  ${GREEN}✓${NC} Distribución: $PRETTY_NAME"
    echo -e "  ${GREEN}✓${NC} Usuario: $(whoami) (UID: $EUID)"
    echo ""
    
    # 2. Permisos
    echo -e "${BLUE}[2/8]${NC} ${CYAN}Permisos${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "$EUID" -eq 0 ]; then
        echo -e "  ${GREEN}✓ PASS${NC} Ejecutando como root"
    else
        echo -e "  ${RED}✗ FAIL${NC} NO es root (UID $EUID)"
        echo -e "  ${YELLOW}→${NC} Ejecuta: sudo $0 -D"
        all_passed=false
    fi
    echo ""
    
    # 3. Dependencias
    echo -e "${BLUE}[3/8]${NC} ${CYAN}Dependencias${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if command -v tshark &> /dev/null; then
        echo -e "  ${GREEN}✓ PASS${NC} tshark $(tshark -v 2>/dev/null | head -1)"
    else
        echo -e "  ${RED}✗ FAIL${NC} tshark NO instalado"
        all_passed=false
    fi
    
    if command -v jq &> /dev/null; then
        echo -e "  ${GREEN}✓ PASS${NC} jq $(jq --version 2>/dev/null)"
    else
        echo -e "  ${YELLOW}⚠ WARN${NC} jq NO instalado (opcional)"
    fi
    
    command -v awk &> /dev/null && echo -e "  ${GREEN}✓ PASS${NC} awk disponible" || all_passed=false
    command -v timeout &> /dev/null && echo -e "  ${GREEN}✓ PASS${NC} timeout disponible" || all_passed=false
    echo ""
    
    # 4. Sistema de alertas
    echo -e "${BLUE}[4/8]${NC} ${CYAN}Sistema de Alertas${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  ${GREEN}✓ PASS${NC} Sistema de alertas integrado en el script"
    command -v notify-send &> /dev/null && echo -e "  ${GREEN}✓ PASS${NC} notify-send disponible" || echo -e "  ${YELLOW}⚠ WARN${NC} notify-send no disponible"
    command -v curl &> /dev/null && echo -e "  ${GREEN}✓ PASS${NC} curl disponible (para webhooks)" || echo -e "  ${YELLOW}⚠ WARN${NC} curl no disponible"
    
    if [ -f "$HOOK_CONFIG_FILE" ]; then
        echo -e "  ${GREEN}✓ INFO${NC} Configuración encontrada: $HOOK_CONFIG_FILE"
    else
        echo -e "  ${YELLOW}⚠ INFO${NC} Sin archivo de configuración (usando defaults)"
    fi
    echo ""
    
    # 5. Red
    echo -e "${BLUE}[5/8]${NC} ${CYAN}Interfaces de Red${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if command -v ip &> /dev/null; then
        local iface_count=$(ip -br link show | wc -l)
        echo -e "  ${GREEN}✓ PASS${NC} Detectadas $iface_count interfaces"
        ip -br link show | while read -r iface status rest; do
            [[ "$status" == "UP" ]] && echo -e "    ${GREEN}●${NC} $iface (UP)" || echo -e "    ${RED}○${NC} $iface ($status)"
        done
    fi
    echo ""
    
    # 6. Captura
    echo -e "${BLUE}[6/8]${NC} ${CYAN}Capacidad de Captura${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "$EUID" -eq 0 ]; then
        local test_pcap="/tmp/netguardian_test_$$.pcap"
        if timeout 3 tshark -i lo -w "$test_pcap" -a duration:2 2>/dev/null; then
            if [ -f "$test_pcap" ] && [ -s "$test_pcap" ]; then
                echo -e "  ${GREEN}✓ PASS${NC} Captura de paquetes funcional"
                rm -f "$test_pcap"
            else
                echo -e "  ${RED}✗ FAIL${NC} No se puede capturar"
                all_passed=false
            fi
        fi
    else
        echo -e "  ${YELLOW}⚠ SKIP${NC} Requiere root"
    fi
    echo ""
    
    # 7. Filesystem
    echo -e "${BLUE}[7/8]${NC} ${CYAN}Sistema de Archivos${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ -d /tmp ] && [ -w /tmp ]; then
        echo -e "  ${GREEN}✓ PASS${NC} /tmp escribible"
        local space=$(df -h /tmp 2>/dev/null | tail -1 | awk '{print $4}')
        echo -e "  ${GREEN}✓ INFO${NC} Espacio disponible: $space"
    else
        echo -e "  ${RED}✗ FAIL${NC} /tmp no escribible"
        all_passed=false
    fi
    echo ""
    
    # 8. Script
    echo -e "${BLUE}[8/8]${NC} ${CYAN}Integridad del Script${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    [ -x "$0" ] && echo -e "  ${GREEN}✓ PASS${NC} Script ejecutable" || echo -e "  ${YELLOW}⚠ WARN${NC} Sin permisos +x"
    
    local funcs=("capture_traffic" "analyze_fingerprinting" "analyze_anomalies" "trigger_alert_pop")
    for func in "${funcs[@]}"; do
        declare -f "$func" > /dev/null && echo -e "  ${GREEN}✓${NC} Función $func OK"
    done
    echo ""
    
    # Resumen
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    if $all_passed; then
        echo -e "${CYAN}║${NC}  ${GREEN}✓ SISTEMA LISTO PARA EJECUTAR NETGUARDIAN${NC}                ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  Ejecuta: ${YELLOW}sudo $0 -i eth0${NC}"
        echo -e "  Probar alertas: ${YELLOW}$0 -t${NC}"
    else
        echo -e "${CYAN}║${NC}  ${RED}✗ ALGUNOS TESTS FALLARON${NC}                                 ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  Revisa los errores arriba y sigue las soluciones sugeridas"
    fi
    echo ""
    
    exit 0
}

################################################################################
# MAIN
################################################################################

main() {
    show_banner
    
    check_dependencies
    check_permissions
    load_oui_database
    
    create_output_structure
    
    # Captura unificada
    capture_traffic
    
    # Análisis
    analyze_fingerprinting
    analyze_anomalies
    
    # Mostrar resumen
    display_final_summary
    
    # Limpieza
    cleanup
    
    log_success "¡NetGuardian completado exitosamente!"
    echo ""
}

################################################################################
# PROCESAMIENTO DE ARGUMENTOS
################################################################################

# Sin argumentos, mostrar ayuda
[ $# -eq 0 ] && show_help && exit 0

while getopts "i:d:o:vnDhltV" opt; do
    case $opt in
        i) INTERFACE="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        v) VERBOSE=true ;;
        n) ENABLE_ALERT_HOOKS=false ;;
        t) test_alert_system ;;
        D) debug_system ;;
        h) show_help; exit 0 ;;
        l) list_interfaces; exit 0 ;;
        V) show_banner; echo -e "${GREEN}Version:${NC} $VERSION"; echo ""; exit 0 ;;
        \?) log_error "Opción inválida: -$OPTARG"; show_help; exit 1 ;;
    esac
done

# Validar interfaz
if [ -z "$INTERFACE" ]; then
    log_error "Debes especificar una interfaz con -i"
    echo ""
    echo "Usa: $0 -l para listar interfaces"
    echo "Usa: $0 -h para ayuda completa"
    echo ""
    exit 1
fi

# Ejecutar
trap cleanup EXIT
main!/bin/bash

################################################################################
# NetGuardian V2.2.0 - All-in-One Edition
# Sistema Unificado de Análisis de Red con Alertas Integradas
# Todo incluido en un solo script portátil
# 
# Versión: 2.2.0 (All-in-One)
# Arquitectura: Monolítica con separación interna de funciones
################################################################################

set -euo pipefail

VERSION="2.2.0-allinone"
INTERFACE=""
DURATION=60
OUTPUT_DIR="netguardian_$(date +%Y%m%d_%H%M%S)"
FINGERPRINT_FILE=""
ANOMALIES_FILE=""
PCAP_FILE=""
TEMP_DIR=""
VERBOSE=false
DEBUG_MODE=false

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Base de datos OUI expandida
declare -A OUI_DB

# Contador global de alertas
ALERT_COUNTER=0

################################################################################
# SECCIÓN 1: SISTEMA DE ALERTAS INTEGRADO
# (Funcionalidad de alert_hooks.sh integrada)
################################################################################

# Configuración de alertas (por defecto)
ENABLE_ALERT_HOOKS=false
ENABLE_DESKTOP_NOTIFY=true
ENABLE_CONSOLE_POPUP=false
ENABLE_SOUND_ALERT=false
ENABLE_WEBHOOK=false
ENABLE_SYSLOG=true
ENABLE_EMAIL_INSTANT=true
ALERT_LOG_FILE="/var/log/netguardian/alerts.log"

# URLs de Webhooks (configurables)
SLACK_WEBHOOK=""
DISCORD_WEBHOOK=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""

# Configuración de sonidos
SOUND_CRITICAL="/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"
SOUND_HIGH="/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"
SOUND_MEDIUM="/usr/share/sounds/freedesktop/stereo/message.oga"

# Cargar configuración externa si existe
HOOK_CONFIG_FILE="/etc/netguardian/alert_hooks.conf"
if [ -f "$HOOK_CONFIG_FILE" ]; then
    # Validar permisos antes de cargar
    local file_perms=$(stat -c %a "$HOOK_CONFIG_FILE" 2>/dev/null || echo "777")
    local file_owner=$(stat -c %u "$HOOK_CONFIG_FILE" 2>/dev/null || echo "999")
    
    if [ "$file_perms" -le 644 ] && { [ "$file_owner" -eq 0 ] || [ "$file_owner" -eq "$EUID" ]; }; then
        source "$HOOK_CONFIG_FILE" 2>/dev/null || true
    else
        echo "[WARNING] Archivo de configuración con permisos inseguros: $HOOK_CONFIG_FILE" >&2
    fi
fi

#-------------------------------------------------------------------------------
# Funciones de Alertas - Popup Terminal
#-------------------------------------------------------------------------------

show_terminal_popup() {
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local color="$YELLOW"
    local symbol="⚠"
    
    case "$severity" in
        CRITICAL)
            color="$RED"
            symbol="🚨"
            ;;
        HIGH)
            color="$YELLOW"
            symbol="⚠"
            ;;
        MEDIUM)
            color="$BLUE"
            symbol="ℹ"
            ;;
    esac
    
    echo ""
    echo -e "${color}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${color}║${NC}  ${symbol}  ${color}ALERT #${alert_id} - ${severity}${NC}                                        ${color}║${NC}"
    echo -e "${color}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${color}║${NC}  Rule: ${rule}${NC}"
    echo -e "${color}║${NC}  ${description}${NC}"
    echo -e "${color}║${NC}  Time: $(date +'%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${color}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Notificación de Escritorio
#-------------------------------------------------------------------------------

send_desktop_notification() {
    [ "$ENABLE_DESKTOP_NOTIFY" != true ] && return
    command -v notify-send &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local urgency="normal"
    local icon="dialog-information"
    
    case "$severity" in
        CRITICAL) urgency="critical"; icon="dialog-error" ;;
        HIGH) urgency="normal"; icon="dialog-warning" ;;
        MEDIUM) urgency="low"; icon="dialog-information" ;;
    esac
    
    local display_user=$(who | grep "(:0)" | awk '{print $1}' | head -1)
    
    if [ -n "$display_user" ]; then
        sudo -u "$display_user" DISPLAY=:0 notify-send \
            --urgency="$urgency" \
            --icon="$icon" \
            --app-name="NetGuardian" \
            "🚨 NetGuardian Alert #$alert_id" \
            "$severity: $description\n\nRule: $rule" \
            2>/dev/null &
    fi
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Popup Consola (Zenity/Dialog)
#-------------------------------------------------------------------------------

send_console_popup() {
    [ "$ENABLE_CONSOLE_POPUP" != true ] && return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    # Intentar con zenity (GUI)
    if command -v zenity &> /dev/null; then
        local display_user=$(who | grep "(:0)" | awk '{print $1}' | head -1)
        
        if [ -n "$display_user" ]; then
            local icon_type="warning"
            [ "$severity" = "CRITICAL" ] && icon_type="error"
            
            sudo -u "$display_user" DISPLAY=:0 zenity \
                --$icon_type \
                --title="NetGuardian Security Alert #$alert_id" \
                --text="<b>Severity:</b> $severity\n<b>Rule:</b> $rule\n\n$description" \
                --width=400 \
                2>/dev/null &
        fi
    # Fallback a dialog (TUI)
    elif command -v dialog &> /dev/null; then
        dialog --title "NetGuardian Alert #$alert_id" \
               --msgbox "SEVERITY: $severity\nRULE: $rule\n\n$description" \
               10 60 2>/dev/null || true
    fi
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Sonido
#-------------------------------------------------------------------------------

play_sound_alert() {
    [ "$ENABLE_SOUND_ALERT" != true ] && return
    
    local severity="$1"
    local sound_file=""
    
    case "$severity" in
        CRITICAL) sound_file="$SOUND_CRITICAL" ;;
        HIGH) sound_file="$SOUND_HIGH" ;;
        MEDIUM) sound_file="$SOUND_MEDIUM" ;;
    esac
    
    # Intentar reproducir con varios reproductores
    if command -v paplay &> /dev/null && [ -f "$sound_file" ]; then
        paplay "$sound_file" 2>/dev/null &
    elif command -v aplay &> /dev/null && [ -f "$sound_file" ]; then
        aplay "$sound_file" 2>/dev/null &
    else
        # Terminal beep según severidad
        case "$severity" in
            CRITICAL) for i in {1..3}; do echo -e "\a"; sleep 0.1; done ;;
            HIGH) for i in {1..2}; do echo -e "\a"; sleep 0.1; done ;;
            MEDIUM) echo -e "\a" ;;
        esac
    fi
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Webhook Slack
#-------------------------------------------------------------------------------

send_slack_webhook() {
    [ "$ENABLE_WEBHOOK" != true ] || [ -z "$SLACK_WEBHOOK" ] && return
    command -v curl &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    local timestamp="$5"
    
    local color="warning"
    local emoji=":warning:"
    
    case "$severity" in
        CRITICAL) color="danger"; emoji=":rotating_light:" ;;
        HIGH) color="warning"; emoji=":warning:" ;;
        MEDIUM) color="good"; emoji=":information_source:" ;;
    esac
    
    local payload=$(cat <<EOF
{
  "username": "NetGuardian",
  "icon_emoji": ":shield:",
  "attachments": [
    {
      "color": "$color",
      "title": "$emoji Alert #$alert_id - $severity",
      "text": "$description",
      "fields": [
        {
          "title": "Rule",
          "value": "$rule",
          "short": true
        },
        {
          "title": "Severity",
          "value": "$severity",
          "short": true
        },
        {
          "title": "Timestamp",
          "value": "$timestamp",
          "short": false
        }
      ],
      "footer": "NetGuardian Security System",
      "ts": $(date +%s)
    }
  ]
}
EOF
)
    
    curl -X POST -H 'Content-type: application/json' \
         --data "$payload" \
         "$SLACK_WEBHOOK" \
         2>/dev/null &
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Webhook Discord
#-------------------------------------------------------------------------------

send_discord_webhook() {
    [ "$ENABLE_WEBHOOK" != true ] || [ -z "$DISCORD_WEBHOOK" ] && return
    command -v curl &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local color_decimal=16776960  # Yellow
    
    case "$severity" in
        CRITICAL) color_decimal=16711680 ;;  # Red
        HIGH) color_decimal=16776960 ;;      # Yellow
        MEDIUM) color_decimal=3447003 ;;     # Blue
    esac
    
    local payload=$(cat <<EOF
{
  "username": "NetGuardian",
  "avatar_url": "https://i.imgur.com/4M34hi2.png",
  "embeds": [
    {
      "title": "🚨 Security Alert #$alert_id",
      "description": "$description",
      "color": $color_decimal,
      "fields": [
        {
          "name": "Severity",
          "value": "$severity",
          "inline": true
        },
        {
          "name": "Rule",
          "value": "$rule",
          "inline": true
        }
      ],
      "footer": {
        "text": "NetGuardian V$VERSION"
      },
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }
  ]
}
EOF
)
    
    curl -X POST -H 'Content-type: application/json' \
         --data "$payload" \
         "$DISCORD_WEBHOOK" \
         2>/dev/null &
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Telegram Bot
#-------------------------------------------------------------------------------

send_telegram_message() {
    [ "$ENABLE_WEBHOOK" != true ] || [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ] && return
    command -v curl &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local emoji="⚠️"
    case "$severity" in
        CRITICAL) emoji="🚨" ;;
        HIGH) emoji="⚠️" ;;
        MEDIUM) emoji="ℹ️" ;;
    esac
    
    local message="$emoji *NetGuardian Alert #$alert_id*

*Severity:* $severity
*Rule:* $rule

*Description:*
$description

_NetGuardian Security System_"
    
    curl -X POST \
         "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
         -d "chat_id=${TELEGRAM_CHAT_ID}" \
         -d "text=${message}" \
         -d "parse_mode=Markdown" \
         2>/dev/null &
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Syslog
#-------------------------------------------------------------------------------

send_syslog() {
    [ "$ENABLE_SYSLOG" != true ] && return
    command -v logger &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local priority="warning"
    case "$severity" in
        CRITICAL) priority="crit" ;;
        HIGH) priority="warning" ;;
        MEDIUM) priority="notice" ;;
    esac
    
    logger -t "netguardian[$alert_id]" -p "security.$priority" \
           "ALERT: $severity - $rule - $description" 2>/dev/null || true
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Log a Archivo
#-------------------------------------------------------------------------------

log_alert_to_file() {
    local alert_id="$1"
    local severity="$2"
    local rule="$3"
    local description="$4"
    local timestamp="$5"
    
    local log_dir=$(dirname "$ALERT_LOG_FILE")
    mkdir -p "$log_dir" 2>/dev/null || true
    
    local log_entry="[$(date +'%Y-%m-%d %H:%M:%S')] ALERT_ID=$alert_id SEVERITY=$severity RULE=$rule DESC=\"$description\" TS=$timestamp"
    
    echo "$log_entry" >> "$ALERT_LOG_FILE" 2>/dev/null || true
}

#-------------------------------------------------------------------------------
# Funciones de Alertas - Email Instantáneo
#-------------------------------------------------------------------------------

send_instant_email() {
    [ "$ENABLE_EMAIL_INSTANT" != true ] && return
    [ "$1" != "MEDIUM" ] && return  # Solo para CRITICAL
    command -v mail &> /dev/null || return
    
    local severity="$1"
    local rule="$2"
    local description="$3"
    local alert_id="$4"
    
    local subject="🚨 CRITICAL NetGuardian Alert #$alert_id"
    local body="NetGuardian Security Alert

Alert ID: $alert_id
Severity: $severity
Rule: $rule
Description: $description
Timestamp: $(date)

This is an automated critical alert from NetGuardian.
Please investigate immediately.

--
NetGuardian Security System"
    
    echo "$body" | msmtp $DEFAULT_EMAIL 2>/dev/null
}

#-------------------------------------------------------------------------------
# Función Principal: Disparar Alerta
#-------------------------------------------------------------------------------

trigger_alert_pop() {
    [ "$ENABLE_ALERT_HOOKS" != true ] && return
    
    local alert_id="$1"
    local severity="$2"
    local rule="$3"
    local description="$4"
    local timestamp="${5:-$(date +%s)}"
    
    # Popup visual en terminal
    show_terminal_popup "$severity" "$rule" "$description" "$alert_id"
    
    # Sonido de alerta
    play_sound_alert "$severity"
    
    # Notificación de escritorio
    send_desktop_notification "$severity" "$rule" "$description" "$alert_id"
    
    # Popup en consola (opcional)
    send_console_popup "$severity" "$rule" "$description" "$alert_id"
    
    # Webhooks
    send_slack_webhook "$severity" "$rule" "$description" "$alert_id" "$timestamp"
    send_discord_webhook "$severity" "$rule" "$description" "$alert_id"
    send_telegram_message "$severity" "$rule" "$description" "$alert_id"
    
    # Logs
    send_syslog "$severity" "$rule" "$description" "$alert_id"
    log_alert_to_file "$alert_id" "$severity" "$rule" "$description" "$timestamp"
    
    # Email instantáneo (solo CRITICAL)
    send_instant_email "$severity" "$rule" "$description" "$alert_id"
}

################################################################################
# SECCIÓN 2: FUNCIONES PRINCIPALES DE NETGUARDIAN
################################################################################

show_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║  ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗║
║  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
║  ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
║  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
║  ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
║  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ║
║                                                                       ║
║          Sistema Unificado de Análisis y Seguridad de Red            ║
║                     All-in-One Edition - V2.2.0                      ║
╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo ""
}

show_help() {
    show_banner
    cat << EOF
${CYAN}DESCRIPCIÓN:${NC}
    NetGuardian es un sistema unificado all-in-one que realiza:
    • Fingerprinting de dispositivos (identificación de MACs)
    • Detección de anomalías de red (ataques y comportamientos sospechosos)
    • Notificaciones en tiempo real (terminal, escritorio, webhooks)
    
    ${GREEN}✨ Versión All-in-One: Todo incluido en un solo script${NC}
    
    Genera DOS archivos JSON desde UNA SOLA captura de tráfico.

${CYAN}USO:${NC}
    $0 -i <interface> [OPTIONS]

${CYAN}OPCIONES REQUERIDAS:${NC}
    -i <interface>     Interfaz de red a monitorear

${CYAN}OPCIONES:${NC}
    -d <seconds>       Duración de captura en segundos (default: 60)
    -o <directory>     Directorio de salida (default: netguardian_TIMESTAMP)
    -v                 Modo verbose (muestra detalles del proceso)
    -n                 No-alerts mode (desactivar notificaciones pop)
    -t                 Test mode (probar sistema de alertas)
    -D                 Modo debug (diagnóstico completo del sistema)
    -h                 Mostrar esta ayuda
    -l                 Listar interfaces disponibles
    -V                 Mostrar versión

${CYAN}EJEMPLOS:${NC}
    # Análisis básico de 60 segundos
    sudo $0 -i eth0

    # Análisis extendido de 5 minutos con modo verbose
    sudo $0 -i wlan0 -d 300 -v

    # Probar sistema de alertas
    $0 -t

    # Diagnóstico del sistema
    $0 -D

${CYAN}CONFIGURACIÓN DE WEBHOOKS:${NC}
    Crea el archivo: /etc/netguardian/alert_hooks.conf
    
    Contenido ejemplo:
        ENABLE_WEBHOOK=true
        SLACK_WEBHOOK="https://hooks.slack.com/services/..."
        DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
        TELEGRAM_BOT_TOKEN="123456789:ABC..."
        TELEGRAM_CHAT_ID="123456789"

${CYAN}SALIDAS:${NC}
    El sistema genera un directorio con 3 archivos:
    
    📁 netguardian_YYYYMMDD_HHMMSS/
       ├── 📄 fingerprint.json      → Inventario de dispositivos
       ├── 📄 anomalies.json        → Alertas de seguridad
       └── 📄 capture.pcap          → Captura de tráfico raw

${CYAN}TIPOS DE ANOMALÍAS DETECTADAS:${NC}
    • MAC Spoofing       → Suplantación de direcciones MAC
    • DHCP Conflicts     → Conflictos en asignación de IPs
    • MAC Changer        → Cambios frecuentes de MAC
    • ARP Spoofing       → Envenenamiento de caché ARP

${CYAN}REQUISITOS:${NC}
    • tshark (Wireshark CLI)
    • jq (opcional, para formato JSON)
    • Permisos de root o grupo wireshark
    • curl (opcional, para webhooks)
    • notify-send (opcional, para notificaciones de escritorio)
EOF
}

list_interfaces() {
    show_banner
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Interfaces de red disponibles:${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    if command -v ip &> /dev/null; then
        echo -e "${BLUE}Estado de interfaces:${NC}"
        ip -br link show | while read -r iface status rest; do
            if [[ "$status" == "UP" ]]; then
                echo -e "  ${GREEN}●${NC} $iface ${GREEN}(UP)${NC}"
            elif [[ "$status" == "DOWN" ]]; then
                echo -e "  ${RED}○${NC} $iface ${RED}(DOWN)${NC}"
            else
                echo -e "  ${YELLOW}○${NC} $iface ${YELLOW}($status)${NC}"
            fi
        done
    else
        tshark -D 2>/dev/null | sed 's/^/  /'
    fi
    echo ""
}

################################################################################
# FUNCIONES DE LOGGING
################################################################################

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $*"
}

log_verbose() {
    [[ "$VERBOSE" == true ]] && echo -e "${BLUE}[VERBOSE]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

log_error() {
    echo -e "${RED}[✗]${NC} $*" >&2
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $*"
}

################################################################################
# FUNCIONES DE VALIDACIÓN
################################################################################

check_dependencies() {
    log "Verificando dependencias..."
    
    local deps=("tshark" "awk" "timeout")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Dependencias faltantes: ${missing[*]}"
        echo ""
        echo -e "${YELLOW}Instalar en Debian/Ubuntu:${NC}"
        echo "  sudo apt install tshark coreutils"
        echo ""
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_warning "jq no está instalado (opcional, pero recomendado)"
        log_warning "Instalar con: sudo apt install jq"
    fi
    
    log_success "Todas las dependencias están instaladas"
}

check_permissions() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Este script requiere permisos de root"
        echo ""
        echo "Ejecuta con: sudo $0 $*"
        echo ""
        exit 1
    fi
}

################################################################################
# BASE DE DATOS OUI
################################################################################

load_oui_database() {
    OUI_DB=(
        # Virtualización
        ["00:50:56"]="VMware"
        ["00:0C:29"]="VMware"
        ["00:05:69"]="VMware"
        ["08:00:27"]="VirtualBox"
        ["52:54:00"]="QEMU/KVM"
        ["00:15:5D"]="Microsoft Hyper-V"
        ["00:1C:42"]="Parallels"
        
        # Raspberry Pi & IoT Boards
        ["B8:27:EB"]="Raspberry Pi"
        ["DC:A6:32"]="Raspberry Pi"
        ["E4:5F:01"]="Raspberry Pi"
        ["28:CD:C1"]="Raspberry Pi"
        
        # Apple
        ["AC:DE:48"]="Apple"
        ["F0:18:98"]="Apple"
        ["D8:9E:3F"]="Apple"
        ["3C:22:FB"]="Apple"
        ["A4:5E:60"]="Apple"
        ["00:1C:B3"]="Apple"
        ["00:23:DF"]="Apple"
        
        # Routers & Networking
        ["DC:CE:C1"]="TP-Link"
        ["50:C7:BF"]="TP-Link"
        ["A4:2B:B0"]="TP-Link"
        ["00:1D:0F"]="Cisco"
        ["00:0A:42"]="Cisco"
        ["A0:63:91"]="Netgear"
        ["E0:91:F5"]="Netgear"
        ["00:1B:2F"]="D-Link"
        ["14:D6:4D"]="D-Link"
        ["00:0B:86"]="Arris"
        
        # Intel/PC
        ["A4:2B:B0"]="Intel"
        ["00:1B:77"]="Intel"
        ["D8:9E:F3"]="Intel"
        ["94:C6:91"]="Intel"
        
        # Móviles - Samsung
        ["00:12:FB"]="Samsung"
        ["5C:0A:5B"]="Samsung"
        ["E8:50:8B"]="Samsung"
        ["CC:3A:61"]="Samsung"
        
        # Móviles - Xiaomi
        ["44:07:0B"]="Xiaomi"
        ["34:CE:00"]="Xiaomi"
        ["F8:C4:F3"]="Xiaomi"
        ["64:09:80"]="Xiaomi"
        
        # Móviles - Huawei
        ["00:18:82"]="Huawei"
        ["F0:79:59"]="Huawei"
        ["78:F5:FD"]="Huawei"
        
        # Móviles - Otros
        ["D4:6E:0E"]="Motorola"
        ["00:26:BA"]="Motorola"
        ["10:68:3F"]="LG"
        ["00:E0:91"]="LG"
        
        # IoT - ESP32/ESP8266
        ["EC:FA:BC"]="Espressif"
        ["24:0A:C4"]="Espressif"
        ["30:AE:A4"]="Espressif"
        ["A4:CF:12"]="Espressif"
        
        # IoT - Otros
        ["68:C6:3A"]="Tuya"
        ["10:D5:61"]="Sonoff"
        ["84:F3:EB"]="Shelly"
        
        # Google
        ["98:FA:9B"]="Google"
        ["DA:A1:19"]="Google"
        ["F4:F5:D8"]="Google"
        
        # Microsoft
        ["00:50:F2"]="Microsoft"
        
        # Printers
        ["00:1E:C2"]="HP"
        ["00:21:5A"]="HP"
        ["00:1B:A9"]="Canon"
        ["00:00:48"]="Epson"
        ["00:80:77"]="Brother"
        
        # Gaming
        ["7C:ED:8D"]="Sony PlayStation"
        ["FC:0F:E6"]="Sony PlayStation"
        ["00:1F:EA"]="Microsoft Xbox"
        ["00:50:F2"]="Microsoft Xbox"
        ["00:17:AB"]="Nintendo"
        
        # TV/Streaming
        ["00:04:4B"]="Roku"
        ["B8:9A:2A"]="Roku"
        ["E4:F0:42"]="Amazon"
    )
}

get_vendor() {
    local mac="$1"
    local oui="${mac:0:8}"
    oui=$(echo "$oui" | tr 'a-z' 'A-Z')
    
    if [[ -n "${OUI_DB[$oui]:-}" ]]; then
        echo "${OUI_DB[$oui]}"
    else
        echo "Unknown"
    fi
}

estimate_device_type() {
    local mac="$1"
    local vendor="$2"
    local protocols="$3"
    local packets="$4"
    
    # Clasificación por vendor (más confiable)
    case "$vendor" in
        *"TP-Link"*|*"Cisco"*|*"Netgear"*|*"D-Link"*|*"Arris"*)
            echo "Router/Gateway"
            return
            ;;
        *"Apple"*)
            if [[ "$mac" == "f0:18:98"* ]]; then
                echo "Mobile Device"
            else
                echo "PC/Workstation"
            fi
            return
            ;;
        *"Raspberry Pi"*)
            if [[ "$packets" -gt 1000 ]]; then
                echo "Server/IoT Hub"
            else
                echo "IoT Device"
            fi
            return
            ;;
        *"Xiaomi"*|*"Tuya"*|*"Espressif"*|*"Sonoff"*|*"Shelly"*)
            echo "IoT Device"
            return
            ;;
        *"Samsung"*|*"Huawei"*|*"Motorola"*|*"LG"*)
            echo "Mobile Device"
            return
            ;;
        *"HP"*|*"Canon"*|*"Epson"*|*"Brother"*)
            echo "Printer"
            return
            ;;
        *"Sony"*|*"Roku"*|*"Amazon"*)
            echo "Smart TV/Streaming"
            return
            ;;
        *"Xbox"*|*"PlayStation"*|*"Nintendo"*)
            echo "Gaming Console"
            return
            ;;
        *"VMware"*|*"VirtualBox"*|*"QEMU"*|*"Hyper-V"*|*"Parallels"*)
            echo "Virtual Machine"
            return
            ;;
        *"Google"*)
            echo "Smart Speaker/Chromecast"
            return
            ;;
    esac
    
    # Clasificación por protocolos
    if [[ "$protocols" == *"IGMP"* ]] || [[ "$protocols" == *"STP"* ]]; then
        echo "Router/Gateway"
    elif [[ "$protocols" == *"MQTT"* ]] || [[ "$protocols" == *"CoAP"* ]]; then
        echo "IoT Device"
    elif [[ "$protocols" == *"QUIC"* ]]; then
        echo "Mobile Device"
    elif [[ "$protocols" == *"IPP"* ]]; then
        echo "Printer"
    elif [[ "$protocols" == *"SSH"* ]] && [[ "$packets" -gt 500 ]]; then
        echo "Server"
    elif [[ "$protocols" == *"SMB"* ]] || [[ "$protocols" == *"SMB2"* ]]; then
        echo "PC/Workstation"
    elif [[ "$protocols" == *"RDP"* ]]; then
        echo "Windows PC"
    elif [[ "$protocols" == *"HTTP"* ]] || [[ "$protocols" == *"TLS"* ]]; then
        if [[ "$packets" -lt 300 ]]; then
            echo "Mobile Device"
        else
            echo "PC/Workstation"
        fi
    else
        echo "Unknown"
    fi
}

################################################################################
# CAPTURA DE TRÁFICO
################################################################################

create_output_structure() {
    log "Creando estructura de directorios..."
    
    mkdir -p "$OUTPUT_DIR"
    TEMP_DIR="$OUTPUT_DIR/.tmp"
    mkdir -p "$TEMP_DIR"/{capture,fingerprint,anomalies}
    
    PCAP_FILE="$OUTPUT_DIR/capture.pcap"
    FINGERPRINT_FILE="$OUTPUT_DIR/fingerprint.json"
    ANOMALIES_FILE="$OUTPUT_DIR/anomalies.json"
    
    log_verbose "Directorio de salida: $OUTPUT_DIR"
    log_verbose "Archivo PCAP: $PCAP_FILE"
}

capture_traffic() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    log_success "Iniciando captura de tráfico unificada"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BLUE}Interfaz:${NC}  $INTERFACE"
    echo -e "  ${BLUE}Duración:${NC}  ${DURATION}s"
    echo -e "  ${BLUE}Filtro:${NC}    Tráfico completo (fingerprint + anomalías)"
    echo ""
    
    log "Capturando tráfico..."
    
    # Captura sin filtro para obtener TODO el tráfico
    timeout "$((DURATION + 5))" tshark -i "$INTERFACE" \
        -w "$PCAP_FILE" \
        -a duration:"$DURATION" \
        2>/dev/null &
    
    local tshark_pid=$!
    
    # Barra de progreso
    for ((i=1; i<=DURATION; i++)); do
        printf "\r  ${YELLOW}Progreso:${NC} ["
        local filled=$((i * 50 / DURATION))
        for ((j=0; j<50; j++)); do
            [ $j -lt $filled ] && printf "█" || printf "░"
        done
        printf "] %3d%%" $((i * 100 / DURATION))
        sleep 1
    done
    echo -e "\n"
    
    wait $tshark_pid 2>/dev/null
    
    if [ ! -f "$PCAP_FILE" ] || [ ! -s "$PCAP_FILE" ]; then
        log_error "Error en la captura de tráfico"
        cleanup
        exit 1
    fi
    
    local pcap_size=$(du -h "$PCAP_FILE" | cut -f1)
    local packet_count=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l)
    
    log_success "Captura completada: $packet_count paquetes ($pcap_size)"
}

################################################################################
# ANÁLISIS: FINGERPRINTING
################################################################################

analyze_fingerprinting() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    log_success "Analizando huellas digitales de dispositivos"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    log "Extrayendo direcciones MAC únicas..."
    tshark -r "$PCAP_FILE" -T fields -e eth.src 2>/dev/null | \
        grep -v "^$" | sort -u > "$TEMP_DIR/fingerprint/macs.txt"
    
    local mac_count=$(wc -l < "$TEMP_DIR/fingerprint/macs.txt")
    log_success "Encontrados $mac_count dispositivos únicos"
    
    log "Procesando información de cada dispositivo..."
    
    local devices_json="["
    local first=true
    local processed=0
    
    while IFS= read -r mac; do
        [[ -z "$mac" ]] && continue
        
        processed=$((processed + 1))
        
        if [[ "$VERBOSE" == true ]]; then
            printf "\r  Procesando dispositivo %d/%d" "$processed" "$mac_count"
        fi
        
        # Estadísticas por MAC
        local stats=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" 2>/dev/null | wc -l)
        [[ $stats -eq 0 ]] && continue
        
        # Bytes totales
        local bytes=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields -e frame.len 2>/dev/null | \
            awk '{sum+=$1} END {print sum+0}')
        
        # Protocolos (top 10)
        local protocols=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields \
            -e _ws.col.Protocol 2>/dev/null | sort | uniq -c | sort -rn | head -10 | \
            awk '{printf "\"%s\":%d,", $2, $1}' | sed 's/,$//')
        
        # Direcciones IPv4
        local ipv4=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields \
            -e ip.src 2>/dev/null | grep -v "^$" | sort -u | \
            awk '{printf "\"%s\",", $0}' | sed 's/,$//')
        
        # Direcciones IPv6
        local ipv6=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields \
            -e ipv6.src 2>/dev/null | grep -v "^$" | sort -u | head -3 | \
            awk '{printf "\"%s\",", $0}' | sed 's/,$//')
        
        # Timestamps
        local first_seen=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields \
            -e frame.time 2>/dev/null | head -1)
        local last_seen=$(tshark -r "$PCAP_FILE" -Y "eth.src == $mac" -T fields \
            -e frame.time 2>/dev/null | tail -1)
        
        # Vendor y tipo de dispositivo
        local vendor=$(get_vendor "$mac")
        local device_type=$(estimate_device_type "$mac" "$vendor" "$protocols" "$stats")
        
        # Calcular throughput promedio
        local avg_packet_size=0
        if [[ $stats -gt 0 ]]; then
            avg_packet_size=$((bytes / stats))
        fi
        
        # Construir JSON del dispositivo
        local device_json=$(cat <<EOF
{
  "mac_address": "$mac",
  "vendor": "$vendor",
  "estimated_type": "$device_type",
  "statistics": {
    "total_packets": $stats,
    "total_bytes": $bytes,
    "avg_packet_size": $avg_packet_size
  },
  "protocols": {$protocols},
  "ip_addresses": {
    "ipv4": [$ipv4],
    "ipv6": [$ipv6]
  },
  "activity": {
    "first_seen": "$first_seen",
    "last_seen": "$last_seen"
  }
}
EOF
)
        
        if $first; then
            devices_json+="$device_json"
            first=false
        else
            devices_json+=",$device_json"
        fi
        
    done < "$TEMP_DIR/fingerprint/macs.txt"
    
    [[ "$VERBOSE" == true ]] && echo ""
    
    devices_json+="]"
    
    # Crear JSON final
    local final_json=$(cat <<EOF
{
  "scan_info": {
    "tool": "NetGuardian",
    "version": "$VERSION",
    "interface": "$INTERFACE",
    "duration": $DURATION,
    "timestamp": "$(date -Iseconds)",
    "pcap_file": "$(basename "$PCAP_FILE")"
  },
  "summary": {
    "total_devices": $mac_count,
    "total_packets_analyzed": $(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l)
  },
  "devices": $devices_json
}
EOF
)
    
    echo "$final_json" | jq '.' > "$FINGERPRINT_FILE" 2>/dev/null || {
        echo "$final_json" > "$FINGERPRINT_FILE"
    }
    
    log_success "Fingerprinting completado: $FINGERPRINT_FILE"
}

################################################################################
# ANÁLISIS: DETECCIÓN DE ANOMALÍAS
################################################################################

increment_alert() {
    ALERT_COUNTER=$((ALERT_COUNTER + 1))
}

# Función para procesar alertas del JSON y disparar popups en tiempo real
process_and_trigger_alerts() {
    local json_file="$1"
    
    # Si no existen alertas o el archivo está vacío, salir
    if [ ! -f "$json_file" ] || [ ! -s "$json_file" ]; then
        return
    fi
    
    # Intentar parsear con jq si está disponible
    if command -v jq &> /dev/null; then
        local alerts_count=$(jq 'length' "$json_file" 2>/dev/null || echo 0)
        
        if [ "$alerts_count" -gt 0 ]; then
            # Procesar cada alerta
            for i in $(seq 0 $((alerts_count - 1))); do
                local alert_id=$(jq -r ".[$i].alert_id // 0" "$json_file" 2>/dev/null)
                local severity=$(jq -r ".[$i].severity // \"UNKNOWN\"" "$json_file" 2>/dev/null)
                local rule=$(jq -r ".[$i].rule // \"UNKNOWN\"" "$json_file" 2>/dev/null)
                local description=$(jq -r ".[$i].description // \"No description\"" "$json_file" 2>/dev/null)
                local timestamp=$(jq -r ".[$i].timestamp // \"N/A\"" "$json_file" 2>/dev/null)
                
                # Disparar alerta pop
                if [ "$alert_id" != "0" ] && [ "$alert_id" != "null" ]; then
                    trigger_alert_pop "$alert_id" "$severity" "$rule" "$description" "$timestamp"
                fi
            done
        fi
    fi
}

analyze_mac_spoofing() {
    log_verbose "Detectando MAC Spoofing..."
    
    tshark -r "$PCAP_FILE" -Y "arp" -T fields \
        -e frame.time_epoch -e eth.src -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 \
        -E separator=, 2>/dev/null > "$TEMP_DIR/anomalies/arp_data.csv"
    
    if [ ! -s "$TEMP_DIR/anomalies/arp_data.csv" ]; then
        echo "[]" > "$TEMP_DIR/anomalies/mac_spoofing.json"
        return
    fi
    
    awk -F, -v counter="$ALERT_COUNTER" 'BEGIN{print"[";f=1;id=counter}{mac=$2;ip=$3;t=$1;if(mac==""||ip=="")next;if(mac in m){if(m[mac]!=ip){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"MAC_SPOOFING_R2\",\"description\":\"Same MAC address with multiple IP addresses\",\"severity\":\"HIGH\",\"details\":{\"mac_address\":\"%s\",\"ip_addresses\":[\"%s\",\"%s\"]},\"protocol\":\"ARP\",\"timestamp\":\"%s\"}\n",id,mac,m[mac],ip,t}}m[mac]=ip;if(ip in im&&im[ip]!=mac){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"MAC_SPOOFING_R3\",\"description\":\"Multiple MAC addresses for same IP\",\"severity\":\"CRITICAL\",\"details\":{\"ip_address\":\"%s\",\"mac_addresses\":[\"%s\",\"%s\"]},\"protocol\":\"ARP\",\"timestamp\":\"%s\"}\n",id,ip,im[ip],mac,t}im[ip]=mac}END{print"]";print id > "/tmp/alert_counter.tmp"}' "$TEMP_DIR/anomalies/arp_data.csv" > "$TEMP_DIR/anomalies/mac_spoofing.json"
    
    if [ -f /tmp/alert_counter.tmp ]; then
        ALERT_COUNTER=$(cat /tmp/alert_counter.tmp)
        rm -f /tmp/alert_counter.tmp
    fi
    
    process_and_trigger_alerts "$TEMP_DIR/anomalies/mac_spoofing.json"
}

analyze_dhcp_conflicts() {
    log_verbose "Detectando conflictos DHCP..."
    
    tshark -r "$PCAP_FILE" -Y "dhcp or bootp" -T fields \
        -e frame.time_epoch -e eth.src -e dhcp.option.dhcp \
        -e dhcp.option.requested_ip_address -e dhcp.ip.your \
        -E separator=, 2>/dev/null > "$TEMP_DIR/anomalies/dhcp_data.csv"
    
    if [ ! -s "$TEMP_DIR/anomalies/dhcp_data.csv" ]; then
        echo "[]" > "$TEMP_DIR/anomalies/dhcp_conflicts.json"
        return
    fi
    
    awk -F, -v counter="$ALERT_COUNTER" 'BEGIN{print"[";f=1;n=0;id=counter}{t=$1;mac=$2;mt=$3;rip=$4;yip=$5;if(t=="")next;if(mt=="6"){n++;lt=t}if(yip!=""&&yip in ia){if(ia[yip]!=mac){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"DHCP_CONFLICT_R1\",\"description\":\"Duplicate IP assignment detected\",\"severity\":\"HIGH\",\"details\":{\"ip_address\":\"%s\",\"mac_addresses\":[\"%s\",\"%s\"]},\"protocol\":\"DHCP\",\"timestamp\":\"%s\"}\n",id,yip,ia[yip],mac,t}}if(yip!="")ia[yip]=mac}END{if(n>5){id++;if(!f)print",";printf"  {\"alert_id\":%d,\"rule\":\"DHCP_CONFLICT_R2\",\"description\":\"DHCP NAK spike detected\",\"severity\":\"MEDIUM\",\"details\":{\"nak_count\":%d},\"protocol\":\"DHCP\",\"timestamp\":\"%s\"}\n",id,n,lt}print"]";print id > "/tmp/alert_counter.tmp"}' "$TEMP_DIR/anomalies/dhcp_data.csv" > "$TEMP_DIR/anomalies/dhcp_conflicts.json"
    
    if [ -f /tmp/alert_counter.tmp ]; then
        ALERT_COUNTER=$(cat /tmp/alert_counter.tmp)
        rm -f /tmp/alert_counter.tmp
    fi
    
    process_and_trigger_alerts "$TEMP_DIR/anomalies/dhcp_conflicts.json"
}

analyze_mac_changer() {
    log_verbose "Detectando cambios de MAC..."
    
    tshark -r "$PCAP_FILE" -Y "arp" -T fields \
        -e frame.time_epoch -e arp.src.proto_ipv4 -e arp.src.hw_mac \
        -E separator=, 2>/dev/null | sort -t, -k2 > "$TEMP_DIR/anomalies/mac_changes.csv"
    
    if [ ! -s "$TEMP_DIR/anomalies/mac_changes.csv" ]; then
        echo "[]" > "$TEMP_DIR/anomalies/mac_changer.json"
        return
    fi
    
    awk -F, -v counter="$ALERT_COUNTER" 'BEGIN{print"[";f=1;id=counter}{t=$1;ip=$2;mac=$3;if(ip==""||mac=="")next;if(ip in im){if(im[ip]!=mac){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"MAC_CHANGER_R1\",\"description\":\"Same IP with different MAC address\",\"severity\":\"MEDIUM\",\"details\":{\"ip_address\":\"%s\",\"old_mac\":\"%s\",\"new_mac\":\"%s\"},\"protocol\":\"ARP\",\"timestamp\":\"%s\"}\n",id,ip,im[ip],mac,t;cc[ip]++}}im[ip]=mac}END{for(ip in cc){if(cc[ip]>=3){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"MAC_CHANGER_R3\",\"description\":\"Frequent MAC changes detected\",\"severity\":\"HIGH\",\"details\":{\"ip_address\":\"%s\",\"change_count\":%d},\"protocol\":\"ARP\",\"timestamp\":\"N/A\"}\n",id,ip,cc[ip]}}print"]";print id > "/tmp/alert_counter.tmp"}' "$TEMP_DIR/anomalies/mac_changes.csv" > "$TEMP_DIR/anomalies/mac_changer.json"
    
    if [ -f /tmp/alert_counter.tmp ]; then
        ALERT_COUNTER=$(cat /tmp/alert_counter.tmp)
        rm -f /tmp/alert_counter.tmp
    fi
    
    process_and_trigger_alerts "$TEMP_DIR/anomalies/mac_changer.json"
}

analyze_arp_spoofing() {
    log_verbose "Detectando ARP Spoofing..."
    
    tshark -r "$PCAP_FILE" -Y "arp.opcode == 2" -T fields \
        -e frame.time_epoch -e eth.src -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 \
        -E separator=, 2>/dev/null > "$TEMP_DIR/anomalies/arp_replies.csv"
    
    if [ ! -s "$TEMP_DIR/anomalies/arp_replies.csv" ]; then
        echo "[]" > "$TEMP_DIR/anomalies/arp_spoofing.json"
        return
    fi
    
    awk -F, -v counter="$ALERT_COUNTER" 'BEGIN{print"[";f=1;id=counter}{t=$1;mac=$2;sip=$3;dip=$4;if(mac==""||sip=="")next;k=sip;if(k in imh){if(imh[k]!=mac){ic[k]++;if(ic[k]>3){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"ARP_SPOOFING_R2\",\"description\":\"ARP cache instability detected\",\"severity\":\"HIGH\",\"details\":{\"ip_address\":\"%s\",\"mac_changes\":%d,\"current_mac\":\"%s\"},\"protocol\":\"ARP\",\"timestamp\":\"%s\"}\n",id,sip,ic[k],mac,t}}}imh[k]=mac;mr[mac]++}END{for(mac in mr){if(mr[mac]>50){id++;if(!f)print",";f=0;printf"  {\"alert_id\":%d,\"rule\":\"ARP_SPOOFING_R3\",\"description\":\"Excessive ARP replies from single MAC\",\"severity\":\"CRITICAL\",\"details\":{\"mac_address\":\"%s\",\"reply_count\":%d},\"protocol\":\"ARP\",\"timestamp\":\"N/A\"}\n",id,mac,mr[mac]}}print"]";print id > "/tmp/alert_counter.tmp"}' "$TEMP_DIR/anomalies/arp_replies.csv" > "$TEMP_DIR/anomalies/arp_spoofing.json"
    
    if [ -f /tmp/alert_counter.tmp ]; then
        ALERT_COUNTER=$(cat /tmp/alert_counter.tmp)
        rm -f /tmp/alert_counter.tmp
    fi
    
    process_and_trigger_alerts "$TEMP_DIR/anomalies/arp_spoofing.json"
}

analyze_anomalies() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    log_success "Detectando anomalías de seguridad"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    ALERT_COUNTER=0
    
    analyze_mac_spoofing
    analyze_dhcp_conflicts
    analyze_mac_changer
    analyze_arp_spoofing
    
    # Combinar todas las alertas
    log "Consolidando alertas..."
    
    local all_alerts="["
    local first=true
    
    for alert_file in "$TEMP_DIR/anomalies/"*.json; do
        if [ -f "$alert_file" ] && [ -s "$alert_file" ]; then
            local content=$(jq -c '.[]' "$alert_file" 2>/dev/null || true)
            if [ -n "$content" ]; then
                while IFS= read -r line; do
                    if $first; then
                        all_alerts+="$line"
                        first=false
                    else
                        all_alerts+=",$line"
                    fi
                done <<< "$content"
            fi
        fi
    done
    
    all_alerts+="]"
    
    # Contar por severidad
    local critical=0
    local high=0
    local medium=0
    
    if command -v jq &> /dev/null; then
        critical=$(echo "$all_alerts" | jq '[.[] | select(.severity=="CRITICAL")] | length' 2>/dev/null || echo 0)
        high=$(echo "$all_alerts" | jq '[.[] | select(.severity=="HIGH")] | length' 2>/dev/null || echo 0)
        medium=$(echo "$all_alerts" | jq '[.[] | select(.severity=="MEDIUM")] | length' 2>/dev/null || echo 0)
    fi
    
    # JSON final
    local final_json=$(cat <<EOF
{
  "scan_info": {
    "tool": "NetGuardian",
    "version": "$VERSION",
    "interface": "$INTERFACE",
    "duration": $DURATION,
    "timestamp": "$(date -Iseconds)",
    "pcap_file": "$(basename "$PCAP_FILE")"
  },
  "summary": {
    "total_alerts": $ALERT_COUNTER,
    "by_severity": {
      "critical": $critical,
      "high": $high,
      "medium": $medium
    }
  },
  "alerts": $all_alerts
}
EOF
)
    
    echo "$final_json" | jq '.' > "$ANOMALIES_FILE" 2>/dev/null || {
        echo "$final_json" > "$ANOMALIES_FILE"
    }
    
    log_success "Análisis de anomalías completado: $ANOMALIES_FILE"
}

################################################################################
# RESUMEN FINAL
################################################################################

display_final_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${CYAN}NETGUARDIAN - ANÁLISIS COMPLETADO${NC}                         ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Información general
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Información del análisis:${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "   ${BLUE}●${NC} Interfaz:         $INTERFACE"
    echo -e "   ${BLUE}●${NC} Duración:         ${DURATION}s"
    echo -e "   ${BLUE}●${NC} Timestamp:        $(date)"
    echo -e "   ${BLUE}●${NC} Directorio:       $OUTPUT_DIR"
    echo ""
    
    # Fingerprinting
    if [ -f "$FINGERPRINT_FILE" ] && command -v jq &> /dev/null; then
        local total_devices=$(jq '.summary.total_devices' "$FINGERPRINT_FILE" 2>/dev/null || echo 0)
        local total_packets=$(jq '.summary.total_packets_analyzed' "$FINGERPRINT_FILE" 2>/dev/null || echo 0)
        
        echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
        echo -e "${BLUE}Fingerprinting de dispositivos:${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
        echo -e "   ${GREEN}✓${NC} Dispositivos detectados:  $total_devices"
        echo -e "   ${GREEN}✓${NC} Paquetes analizados:      $total_packets"
        echo ""
    fi
    
    # Anomalías
    if [ -f "$ANOMALIES_FILE" ] && command -v jq &> /dev/null; then
        local total_alerts=$(jq '.summary.total_alerts' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        local critical=$(jq '.summary.by_severity.critical' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        local high=$(jq '.summary.by_severity.high' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        local medium=$(jq '.summary.by_severity.medium' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        
        echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
        echo -e "${BLUE}Detección de anomalías:${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
        echo -e "   ${BLUE}Total de alertas:${NC}     $total_alerts"
        
        if [ "$critical" -gt 0 ]; then
            echo -e "   ${RED}●${NC} Críticas:            ${RED}$critical${NC}"
        fi
        if [ "$high" -gt 0 ]; then
            echo -e "   ${YELLOW}●${NC} Altas:               ${YELLOW}$high${NC}"
        fi
        if [ "$medium" -gt 0 ]; then
            echo -e "   ${BLUE}●${NC} Medias:              ${BLUE}$medium${NC}"
        fi
        
        if [ "$total_alerts" -eq 0 ]; then
            echo -e "   ${GREEN}✓${NC} No se detectaron amenazas"
        fi
        echo ""
    fi
    
    # Archivos generados
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Archivos generados:${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "   ${BLUE}●${NC} fingerprint.json  → Inventario de dispositivos"
    echo -e "   ${BLUE}●${NC} anomalies.json    → Reporte de seguridad"
    echo -e "   ${BLUE}●${NC} capture.pcap      → Captura raw de tráfico"
    echo ""
    
    # Recomendaciones
    if [ -f "$ANOMALIES_FILE" ] && command -v jq &> /dev/null; then
        local total_alerts=$(jq '.summary.total_alerts' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        local critical=$(jq '.summary.by_severity.critical' "$ANOMALIES_FILE" 2>/dev/null || echo 0)
        
        if [ "$critical" -gt 0 ]; then
            echo -e "${RED}⚠️  ATENCIÓN:${NC} Se detectaron ${RED}$critical alertas CRÍTICAS${NC}"
            echo -e "    Revisa inmediatamente el archivo: ${YELLOW}$ANOMALIES_FILE${NC}"
            echo ""
        elif [ "$total_alerts" -gt 0 ]; then
            echo -e "${YELLOW}ℹ️  INFO:${NC} Se detectaron $total_alerts anomalías"
            echo -e "    Revisa el archivo: ${YELLOW}$ANOMALIES_FILE${NC}"
            echo ""
        fi
    fi
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

################################################################################
# LIMPIEZA
################################################################################

cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        log_verbose "Limpiando archivos temporales..."
        rm -rf "$TEMP_DIR"
    fi
    
    rm -f /tmp/alert_counter.tmp
}

################################################################################
# MODO TEST
################################################################################

test_alert_system() {
    show_banner
    echo "Testing NetGuardian Alert System..."
    echo ""
    
    echo "Testing MEDIUM alert..."
    trigger_alert_pop 999 "MEDIUM" "TEST_RULE" "This is a test medium alert" "$(date +%s)"
    sleep 2
    
    echo "Testing HIGH alert..."
    trigger_alert_pop 998 "HIGH" "TEST_RULE" "This is a test high alert" "$(date +%s)"
    sleep 2
    
    echo "Testing CRITICAL alert..."
    trigger_alert_pop 997 "CRITICAL" "TEST_RULE" "This is a test critical alert" "$(date +%s)"
    
    echo ""
    echo "Alert system test completed!"
    echo ""
    exit 0
}

################################################################################
# MODO DEBUG
################################################################################

debug_system() {
    show_banner
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}DIAGNÓSTICO COMPLETO DEL SISTEMA${NC}                         ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    local all_passed=true
    
    # 1. Sistema
    echo -e "${BLUE}[1/8]${NC} ${CYAN}Información del Sistema${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  ${GREEN}✓${NC} Sistema: $(uname -s) $(uname -r)"
    echo -e "  ${GREEN}✓${NC} Arquitectura: $(uname -m)"
    [ -f /etc/os-release ] && source /etc/os-release && echo -e "  ${GREEN}✓${NC} Distribución: $PRETTY_NAME"
    echo -e "  ${GREEN}✓${NC} Usuario: $(whoami) (UID: $EUID)"
    echo ""
    
    # 2. Permisos
    echo -e "${BLUE}[2/8]${NC} ${CYAN}Permisos${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "$EUID" -eq 0 ]; then
        echo -e "  ${GREEN}✓ PASS${NC} Ejecutando como root"
    else
        echo -e "  ${RED}✗ FAIL${NC} NO es root (UID $EUID)"
        echo -e "  ${YELLOW}→${NC} Ejecuta: sudo $0 -D"
        all_passed=false
    fi
    echo ""
    
    # 3. Dependencias
    echo -e "${BLUE}[3/8]${NC} ${CYAN}Dependencias${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if command -v tshark &> /dev/null; then
        echo -e "  ${GREEN}✓ PASS${NC} tshark $(tshark -v 2>/dev/null | head -1)"
    else
        echo -e "  ${RED}✗ FAIL${NC} tshark NO instalado"
        all_passed=false
    fi
    
    if command -v jq &> /dev/null; then
        echo -e "  ${GREEN}✓ PASS${NC} jq $(jq --version 2>/dev/null)"
    else
        echo -e "  ${YELLOW}⚠ WARN${NC} jq NO instalado (opcional)"
    fi
    
    command -v awk &> /dev/null && echo -e "  ${GREEN}✓ PASS${NC} awk disponible" || all_passed=false
    command -v timeout &> /dev/null && echo -e "  ${GREEN}✓ PASS${NC} timeout disponible" || all_passed=false
    echo ""
    
    # 4. Sistema de alertas
    echo -e "${BLUE}[4/8]${NC} ${CYAN}Sistema de Alertas${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  ${GREEN}✓ PASS${NC} Sistema de alertas integrado en el script"
    command -v notify-send &> /dev/null && echo -e "  ${GREEN}✓ PASS${NC} notify-send disponible" || echo -e "  ${YELLOW}⚠ WARN${NC} notify-send no disponible"
    command -v curl &> /dev/null && echo -e "  ${GREEN}✓ PASS${NC} curl disponible (para webhooks)" || echo -e "  ${YELLOW}⚠ WARN${NC} curl no disponible"
    
    if [ -f "$HOOK_CONFIG_FILE" ]; then
        echo -e "  ${GREEN}✓ INFO${NC} Configuración encontrada: $HOOK_CONFIG_FILE"
    else
        echo -e "  ${YELLOW}⚠ INFO${NC} Sin archivo de configuración (usando defaults)"
    fi
    echo ""
    
    # 5. Red
    echo -e "${BLUE}[5/8]${NC} ${CYAN}Interfaces de Red${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if command -v ip &> /dev/null; then
        local iface_count=$(ip -br link show | wc -l)
        echo -e "  ${GREEN}✓ PASS${NC} Detectadas $iface_count interfaces"
        ip -br link show | while read -r iface status rest; do
            [[ "$status" == "UP" ]] && echo -e "    ${GREEN}●${NC} $iface (UP)" || echo -e "    ${RED}○${NC} $iface ($status)"
        done
    fi
    echo ""
    
    # 6. Captura
    echo -e "${BLUE}[6/8]${NC} ${CYAN}Capacidad de Captura${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "$EUID" -eq 0 ]; then
        local test_pcap="/tmp/netguardian_test_$$.pcap"
        if timeout 3 tshark -i lo -w "$test_pcap" -a duration:2 2>/dev/null; then
            if [ -f "$test_pcap" ] && [ -s "$test_pcap" ]; then
                echo -e "  ${GREEN}✓ PASS${NC} Captura de paquetes funcional"
                rm -f "$test_pcap"
            else
                echo -e "  ${RED}✗ FAIL${NC} No se puede capturar"
                all_passed=false
            fi
        fi
    else
        echo -e "  ${YELLOW}⚠ SKIP${NC} Requiere root"
    fi
    echo ""
    
    # 7. Filesystem
    echo -e "${BLUE}[7/8]${NC} ${CYAN}Sistema de Archivos${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ -d /tmp ] && [ -w /tmp ]; then
        echo -e "  ${GREEN}✓ PASS${NC} /tmp escribible"
        local space=$(df -h /tmp 2>/dev/null | tail -1 | awk '{print $4}')
        echo -e "  ${GREEN}✓ INFO${NC} Espacio disponible: $space"
    else
        echo -e "  ${RED}✗ FAIL${NC} /tmp no escribible"
        all_passed=false
    fi
    echo ""
    
    # 8. Script
    echo -e "${BLUE}[8/8]${NC} ${CYAN}Integridad del Script${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    [ -x "$0" ] && echo -e "  ${GREEN}✓ PASS${NC} Script ejecutable" || echo -e "  ${YELLOW}⚠ WARN${NC} Sin permisos +x"
    
    local funcs=("capture_traffic" "analyze_fingerprinting" "analyze_anomalies" "trigger_alert_pop")
    for func in "${funcs[@]}"; do
        declare -f "$func" > /dev/null && echo -e "  ${GREEN}✓${NC} Función $func OK"
    done
    echo ""
    
    # Resumen
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    if $all_passed; then
        echo -e "${CYAN}║${NC}  ${GREEN}✓ SISTEMA LISTO PARA EJECUTAR NETGUARDIAN${NC}                ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  Ejecuta: ${YELLOW}sudo $0 -i eth0${NC}"
        echo -e "  Probar alertas: ${YELLOW}$0 -t${NC}"
    else
        echo -e "${CYAN}║${NC}  ${RED}✗ ALGUNOS TESTS FALLARON${NC}                                 ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  Revisa los errores arriba y sigue las soluciones sugeridas"
    fi
    echo ""
    
    exit 0
}

################################################################################
# MAIN
################################################################################

main() {
    show_banner
    
    check_dependencies
    check_permissions
    load_oui_database
    
    create_output_structure
    
    # Captura unificada
    capture_traffic
    
    # Análisis
    analyze_fingerprinting
    analyze_anomalies
    
    # Mostrar resumen
    display_final_summary
    
    # Limpieza
    cleanup
    
    log_success "¡NetGuardian completado exitosamente!"
    echo ""
}

################################################################################
# PROCESAMIENTO DE ARGUMENTOS
################################################################################

# Sin argumentos, mostrar ayuda
[ $# -eq 0 ] && show_help && exit 0

while getopts "i:d:o:vnDhltV" opt; do
    case $opt in
        i) INTERFACE="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        v) VERBOSE=true ;;
        n) ENABLE_ALERT_HOOKS=false ;;
        t) test_alert_system ;;
        D) debug_system ;;
        h) show_help; exit 0 ;;
        l) list_interfaces; exit 0 ;;
        V) show_banner; echo -e "${GREEN}Version:${NC} $VERSION"; echo ""; exit 0 ;;
        \?) log_error "Opción inválida: -$OPTARG"; show_help; exit 1 ;;
    esac
done

# Validar interfaz
if [ -z "$INTERFACE" ]; then
    log_error "Debes especificar una interfaz con -i"
    echo ""
    echo "Usa: $0 -l para listar interfaces"
    echo "Usa: $0 -h para ayuda completa"
    echo ""
    exit 1
fi

# Ejecutar
trap cleanup EXIT
main
