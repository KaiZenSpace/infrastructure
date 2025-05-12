#!/bin/bash
# WireGuard Manager - Konfigurationsdatei
# Diese Datei enthält alle Konfigurationsparameter für den WireGuard Manager

# Umask setzen, damit neue Dateien nur für den Eigentümer lesbar sind
umask 077

# Verzeichnispfade
CONFIG_DIR="/root/../config"
WG_CONFS_DIR="$CONFIG_DIR/wg_confs"
SERVER_CONF="$WG_CONFS_DIR/wg0.conf"
PEERS_DIR="$CONFIG_DIR"

# Netzwerk-Konfiguration
IP_BASE="10.13.13"
SERVER_ENDPOINT="46.202.153.125:51820"
DNS_SERVER="172.29.0.3"

# Max. Anzahl der erlaubten Clients (-1 für unbegrenzt)
MAX_CLIENTS=5

# Status- und Datendateien
LAST_SEEN_FILE="$CONFIG_DIR/client_last_seen.dat"

# WireGuard Interface Namen
WG_INTERFACE="wg0"
