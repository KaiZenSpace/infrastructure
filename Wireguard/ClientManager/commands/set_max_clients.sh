#!/bin/bash
# WireGuard Manager - Befehl zum Setzen der maximalen Client-Anzahl

# Kommando: set-max-clients - Maximale Anzahl von Clients setzen
set_max_clients() {
    local max_clients="$1"
    
    # Prüfen ob ein Wert angegeben wurde
    if [ -z "$max_clients" ]; then
        error "Keine Client-Anzahl angegeben. Verwendung: wg-manager set-max-clients <n>"
    fi
    
    # Prüfen ob die Eingabe eine Zahl ist
    if ! [[ "$max_clients" =~ ^-?[0-9]+$ ]]; then
        error "Ungültige Eingabe. Bitte geben Sie eine Zahl an."
    fi
    
    # Konfigurationsdatei aktualisieren
    temp_file=$(mktemp)
    
    # Bearbeite die Konfigurationsdatei, um MAX_CLIENTS zu ändern
    sed "s/^MAX_CLIENTS=.*/MAX_CLIENTS=$max_clients/" "$CONFIG_FILE" > "$temp_file"
    
    # Temporäre Datei zurückkopieren
    cp "$temp_file" "$CONFIG_FILE"
    rm "$temp_file"
    
    # Globale Variable aktualisieren
    MAX_CLIENTS=$max_clients
    
    echo "Maximale Client-Anzahl wurde auf $max_clients gesetzt."
}