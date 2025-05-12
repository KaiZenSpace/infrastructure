#!/bin/bash
# WireGuard Manager - Peer-Management Funktionen
# Diese Datei enthält Funktionen zur Verwaltung von Peers

# Hilfsfunktion: Client löschen, der am längsten offline ist
remove_oldest_inactive_peer() {
    local oldest_peer=""
    local oldest_time=$(date +%s)
    local current_time=$(date +%s)
    
    # Last-Seen-Datei muss existieren
    if [ ! -f "$LAST_SEEN_FILE" ]; then
        error "Keine Last-Seen-Datei gefunden. Automatische Löschung nicht möglich."
    fi
    
    # Aktuelle Verbindungen holen - mit latest_handshake
    # Forciere eine Aktualisierung des WireGuard Status
    wg show > /dev/null 2>&1
    connections=$(get_connections)
    
    # Alle Peers durchgehen und den ältesten inaktiven finden
    while IFS=: read -r peer timestamp; do
        # Prüfen ob der Peer noch in der Konfiguration existiert
        if ! grep -q "# $peer$" "$SERVER_CONF"; then
            continue
        fi
        
        # Public Key des Peers holen
        pubkey=$(grep -A1 "# $peer$" "$SERVER_CONF" | grep "PublicKey" | cut -d' ' -f3)
        
        # Prüfen ob der Peer verbunden ist
        if echo "$connections" | grep -q "$pubkey"; then
            # Verbundene Peers überspringen
            continue
        fi
        
        # Prüfen ob dieser Peer länger offline ist als der bisher gefundene älteste
        if [ -z "$oldest_peer" ] || [ "$timestamp" -lt "$oldest_time" ]; then
            oldest_peer="$peer"
            oldest_time="$timestamp"
        fi
    done < "$LAST_SEEN_FILE"
    
    # Wenn kein inaktiver Peer gefunden wurde
    if [ -z "$oldest_peer" ]; then
        error "Konnte keinen inaktiven Peer zum Löschen finden. Limit kann nicht eingehalten werden."
    fi
    
    # Den ältesten inaktiven Peer löschen
    last_seen_str=$(format_timestamp "$oldest_time")
    echo "Maximale Client-Anzahl erreicht. Der am längsten inaktive Client '$oldest_peer' (zuletzt online: $last_seen_str) wird gelöscht."
    remove_peer "$oldest_peer" "auto"
}

# Hilfsfunktion: Peer-Verzeichnis erstellen
create_peer_dir() {
    local peer_name="$1"
    mkdir -p "$PEERS_DIR/$peer_name"
}

# Hilfsfunktion: Schlüssel für einen Peer generieren
generate_peer_keys() {
    local peer_name="$1"
    local peer_dir="$PEERS_DIR/$peer_name"
    
    # Schlüssel generieren (mit sicheren Berechtigungen)
    wg genkey | tee "$peer_dir/privatekey-$peer_name" | wg pubkey > "$peer_dir/publickey-$peer_name"
    wg genpsk > "$peer_dir/presharedkey-$peer_name"
    
    # Berechtigungen zusätzlich explizit setzen
    chmod 600 "$peer_dir/privatekey-$peer_name"
    chmod 600 "$peer_dir/presharedkey-$peer_name"
}

# Hilfsfunktion: Public Key eines Peers abrufen
get_peer_pubkey() {
    local peer_name="$1"
    
    # Public Key des Peers aus der Konfigurationsdatei extrahieren
    grep -A1 "# $peer_name$" "$SERVER_CONF" | grep "PublicKey" | cut -d' ' -f3
}

# Hilfsfunktion: Preshared Key eines Peers abrufen
get_peer_preshared_key() {
    local peer_name="$1"
    
    # Preshared Key des Peers aus dem Peer-Verzeichnis abrufen
    cat "$PEERS_DIR/$peer_name/presharedkey-$peer_name"
}

# Hilfsfunktion: Prüfen ob ein Peer existiert
peer_exists() {
    local peer_name="$1"
    
    # Prüfen ob der Peer in der Konfigurationsdatei existiert
    grep -q "# $peer_name$" "$SERVER_CONF"
}

# Hilfsfunktion: Prüfen ob ein Peer verbunden ist
is_peer_connected() {
    local peer_name="$1"
    local pubkey=$(get_peer_pubkey "$peer_name")
    local connections=$(get_connections)
    local last_handshake=0
    local current_time=$(date +%s)
    
    # Wenn kein Public Key gefunden wurde
    if [ -z "$pubkey" ]; then
        return 1
    fi
    
    # Verbindungsstatus aus WireGuard direkt auslesen
    if connection_line=$(echo "$connections" | grep "$pubkey"); then
        last_handshake=$(echo "$connection_line" | awk '{print $5}')
        
        if [ "$last_handshake" != "0" ]; then
            # Zeitspanne seit dem letzten Handshake in Sekunden
            seconds_since_handshake=$((current_time - last_handshake))
            
            # Wenn der letzte Handshake weniger als 3 Minuten her ist, gilt der Peer als verbunden
            if [ "$seconds_since_handshake" -lt 180 ]; then
                return 0
            else
                # Wenn nicht mehr verbunden, aber Handshake existiert, Last-Seen aktualisieren
                update_last_seen "$peer_name" "$last_handshake"
                return 1
            fi
        fi
    fi
    
    # Peer nicht verbunden
    return 1
}

# Hilfsfunktion: Server-Konfiguration aktualisieren für einen neuen Peer
update_server_config() {
    local peer_name="$1"
    local client_pubkey="$2"
    local preshared_key="$3"
    local ip="$4"
    
    # Server-Konfig aktualisieren
    cat >> "$SERVER_CONF" << EOF
[Peer]
# $peer_name
PublicKey = $client_pubkey
PresharedKey = $preshared_key
AllowedIPs = $IP_BASE.$ip/32
EOF
}

# Hilfsfunktion: Client-Konfiguration erstellen
create_client_config() {
    local peer_name="$1"
    local client_privkey="$2"
    local preshared_key="$3"
    local ip="$4"
    local server_pubkey
    
    # Server Public Key holen
    server_pubkey=$(grep PrivateKey "$SERVER_CONF" | cut -d' ' -f3 | wg pubkey)
    
    # Client-Konfig erstellen
    cat > "$PEERS_DIR/$peer_name/$peer_name.conf" << EOF
[Interface]
Address = $IP_BASE.$ip
PrivateKey = $client_privkey
ListenPort = 51820
DNS = $DNS_SERVER

[Peer]
PublicKey = $server_pubkey
PresharedKey = $preshared_key
Endpoint = $SERVER_ENDPOINT
AllowedIPs = 0.0.0.0/0
EOF
}

# Hilfsfunktion: QR-Code für Client-Konfiguration erstellen
create_qr_code() {
    local peer_name="$1"
    
    # QR-Code generieren (erfordert qrencode)
    qrencode -t png -o "$PEERS_DIR/$peer_name/$peer_name.png" < "$PEERS_DIR/$peer_name/$peer_name.conf"
}

# Hilfsfunktion: Peer bei WireGuard hinzufügen/aktualisieren
apply_peer_config() {
    local peer_name="$1"
    local pubkey="$2"
    local ip="$3"
    local preshared_key_path="$PEERS_DIR/$peer_name/presharedkey-$peer_name"
    
    # WireGuard direkt aktualisieren
    wg set $WG_INTERFACE peer "$pubkey" preshared-key "$preshared_key_path" allowed-ips "$IP_BASE.$ip/32"
}

# Hilfsfunktion: Peer aus WireGuard entfernen
remove_peer_from_wg() {
    local pubkey="$1"
    
    # Peer aus WireGuard entfernen
    wg set $WG_INTERFACE peer "$pubkey" remove
}

# Hilfsfunktion: Peer aus Konfigurationsdatei entfernen
remove_peer_from_config() {
    local peer_name="$1"
    
    # Temporäre Datei für die neue Konfiguration erstellen
    temp_conf=$(mktemp)
    
    # Peer-Abschnitt aus der Konfigurationsdatei entfernen
    awk -v peer="# $peer_name" '
    /^\[Peer\]/ {
        if ((getline) && $0 ~ peer) {
            # Überspringen bis zum nächsten Abschnitt oder Ende der Datei
            while (getline) {
                if ($0 ~ /^\[/) {
                    print $0;
                    break;
                }
            }
            next;
        }
        else {
            print "[Peer]";
            print $0;
        }
        next;
    }
    { print }
    ' "$SERVER_CONF" > "$temp_conf"
    
    # Temporäre Datei zurückkopieren
    cp "$temp_conf" "$SERVER_CONF"
    rm "$temp_conf"
}

# Hilfsfunktion: Peer-Dateien entfernen
remove_peer_files() {
    local peer_name="$1"
    local auto_delete="$2"
    
    if [ "$auto_delete" = "auto" ]; then
        # Bei automatischer Löschung immer löschen
        rm -rf "$PEERS_DIR/$peer_name"
        echo "Konfigurationsdateien für '$peer_name' wurden automatisch gelöscht."
    else
        # Bei manueller Löschung nachfragen
        read -p "Sollen die Konfigurationsdateien für '$peer_name' gelöscht werden? (j/N): " should_delete
        if [[ $should_delete =~ ^[Jj]$ ]]; then
            rm -rf "$PEERS_DIR/$peer_name"
            echo "Konfigurationsdateien für '$peer_name' wurden gelöscht."
        fi
    fi
}

# Hilfsfunktion: Last-Seen-Eintrag für einen Peer löschen
remove_last_seen_entry() {
    local peer_name="$1"
    
    # Last-Seen-Eintrag löschen
    if [ -f "$LAST_SEEN_FILE" ]; then
        grep -v "^$peer_name:" "$LAST_SEEN_FILE" > "${LAST_SEEN_FILE}.tmp" || true
        mv "${LAST_SEEN_FILE}.tmp" "$LAST_SEEN_FILE"
    fi
}