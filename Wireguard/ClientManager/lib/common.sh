#!/bin/bash
# WireGuard Manager - Gemeinsame Hilfsfunktionen
# Diese Datei enthält allgemeine Funktionen, die von verschiedenen Teilen des Skripts verwendet werden

# Hilfsfunktion: Fehler ausgeben und beenden
error() {
    echo "FEHLER: $1" >&2
    exit 1
}

# Hilfsfunktion: Information ausgeben
info() {
    echo "INFO: $1"
}

# Hilfsfunktion: Warnung ausgeben
warning() {
    echo "WARNUNG: $1" >&2
}

# Hilfsfunktion: Prüfen ob WireGuard läuft
check_wireguard() {
    if ! wg show > /dev/null 2>&1; then
        error "WireGuard scheint nicht zu laufen. Bitte starten Sie den WireGuard-Dienst."
    fi
}

# Hilfsfunktion: Prüfen ob die Konfigurationsdatei existiert
check_config() {
    if [ ! -f "$SERVER_CONF" ]; then
        error "WireGuard Konfigurationsdatei nicht gefunden: $SERVER_CONF"
    fi
}

# Hilfsfunktion: Update des Last-Seen Timestamps
update_last_seen() {
    local peer_name="$1"
    local timestamp="$2"
    
    # Wenn keine Zeit angegeben, aktuelle Zeit verwenden
    if [ -z "$timestamp" ]; then
        timestamp=$(date +%s)
    fi
    
    # Last-Seen-Datei erstellen falls nicht vorhanden
    touch "$LAST_SEEN_FILE"
    
    # Temporäre Datei für Update
    temp_file=$(mktemp)
    
    # Aktualisiere Eintrag oder füge neuen hinzu
    grep -v "^$peer_name:" "$LAST_SEEN_FILE" > "$temp_file" || true
    echo "$peer_name:$timestamp" >> "$temp_file"
    
    # Zurückkopieren
    mv "$temp_file" "$LAST_SEEN_FILE"
}

# Hilfsfunktion: Peer Last-Seen Timestamp auslesen
get_last_seen() {
    local peer_name="$1"
    
    # Prüfen ob die Datei existiert
    if [ ! -f "$LAST_SEEN_FILE" ]; then
        echo "0"
        return
    fi
    
    # Timestamp auslesen, oder 0 wenn nicht gefunden
    grep "^$peer_name:" "$LAST_SEEN_FILE" | cut -d':' -f2 || echo "0"
}

# Hilfsfunktion: Timestamp in lesbare Form umwandeln
format_timestamp() {
    local timestamp="$1"
    
    # Wenn Timestamp 0 ist, "Nie" zurückgeben
    if [ "$timestamp" = "0" ]; then
        echo "Nie"
    else
        date -d @"$timestamp" "+%Y-%m-%d %H:%M:%S"
    fi
}

# Hilfsfunktion: Anzahl der aktuellen Clients ermitteln
get_client_count() {
    grep -c "^\[Peer\]" "$SERVER_CONF"
}

# Hilfsfunktion: Aktuelle Verbindungsinformationen abrufen
get_connections() {
    wg show $WG_INTERFACE dump
}