#!/bin/bash
# WireGuard Manager - Hauptskript
# Verwendung: wg-manager [command] [parameters]

# Aktuelles Verzeichnis des Skripts ermitteln
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Konfigurationsdatei definieren und laden
CONFIG_FILE="$SCRIPT_DIR/config.sh"
source "$CONFIG_FILE"

# Bibliotheken laden
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/ip_management.sh"
source "$SCRIPT_DIR/lib/peer_management.sh"

# Kommandos laden
source "$SCRIPT_DIR/commands/list_peers.sh"
source "$SCRIPT_DIR/commands/add_peer.sh"
source "$SCRIPT_DIR/commands/remove_peer.sh"
source "$SCRIPT_DIR/commands/set_max_clients.sh"
source "$SCRIPT_DIR/commands/help.sh"

# Hauptfunktion zur Verarbeitung der Kommandos
main() {
    case "$1" in
        list-peers)
            list_peers
            ;;
        add-peer)
            add_peer "$2"
            ;;
        remove-peer)
            remove_peer "$2"
            ;;
        set-max-clients)
            set_max_clients "$2"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo "Unbekannter Befehl: $1"
            echo "Verwenden Sie 'wg-manager help' für eine Liste der verfügbaren Befehle."
            exit 1
            ;;
    esac
}

# Skript ausführen
main "$@"