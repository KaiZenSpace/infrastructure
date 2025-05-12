#!/bin/bash
# WireGuard Manager - Befehl für die Hilfe-Anzeige

# Kommando: help - Hilfe anzeigen
show_help() {
    echo "WireGuard Manager - Verwaltungstool für WireGuard"
    echo ""
    echo "Verwendung:"
    echo "  wg-manager list-peers         - Alle Peers auflisten"
    echo "  wg-manager add-peer <name>    - Neuen Peer hinzufügen"
    echo "  wg-manager remove-peer <name> - Peer entfernen"
    echo "  wg-manager set-max-clients <n> - Maximale Anzahl von Clients setzen (-1 für unbegrenzt)"
    echo "  wg-manager help               - Diese Hilfe anzeigen"
    echo ""
    echo "Konfiguration:"
    echo "  Die Konfigurationsdatei befindet sich unter: $CONFIG_FILE"
}