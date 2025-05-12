#!/bin/bash
# WireGuard Manager - Befehl zum Hinzufügen eines Peers

# Kommando: add-peer - Neuen Peer hinzufügen
add_peer() {
    local peer_name="$1"
    
    # Prüfen ob ein Name angegeben wurde
    if [ -z "$peer_name" ]; then
        error "Kein Peer-Name angegeben. Verwendung: wg-manager add-peer <name>"
    fi
    
    check_wireguard
    check_config
    
    # Prüfen ob der Peer bereits existiert
    if peer_exists "$peer_name"; then
        error "Ein Peer mit dem Namen '$peer_name' existiert bereits."
    fi
    
    # Aktuelle Client-Anzahl prüfen
    current_clients=$(get_client_count)
    
    # Wenn MAX_CLIENTS >= 0 ist und das Limit erreicht wurde
    if [ "$MAX_CLIENTS" -ge 0 ] && [ "$current_clients" -ge "$MAX_CLIENTS" ]; then
        # Versuchen den ältesten inaktiven Peer zu löschen
        remove_oldest_inactive_peer
    fi
    
    # Peer-Verzeichnis erstellen
    create_peer_dir "$peer_name"
    
    # Schlüssel generieren
    generate_peer_keys "$peer_name"
    
    client_privkey=$(cat "$PEERS_DIR/$peer_name/privatekey-$peer_name")
    client_pubkey=$(cat "$PEERS_DIR/$peer_name/publickey-$peer_name")
    preshared_key=$(cat "$PEERS_DIR/$peer_name/presharedkey-$peer_name")
    
    # Nächste freie IP finden
    next_ip=$(find_next_ip)
    
    # Client-Konfiguration erstellen
    create_client_config "$peer_name" "$client_privkey" "$preshared_key" "$next_ip"
    
    # Server-Konfiguration aktualisieren
    update_server_config "$peer_name" "$client_pubkey" "$preshared_key" "$next_ip"
    
    # QR-Code generieren
    create_qr_code "$peer_name"
    
    # WireGuard aktualisieren
    apply_peer_config "$peer_name" "$client_pubkey" "$next_ip"
    
    # Initial LastSeen setzen (noch nie gesehen)
    update_last_seen "$peer_name" "0"
    
    echo "Peer '$peer_name' wurde erfolgreich mit der IP $IP_BASE.$next_ip erstellt."
    echo "Die Konfigurationsdatei befindet sich unter $PEERS_DIR/$peer_name/$peer_name.conf"
    echo "Ein QR-Code für mobile Geräte wurde unter $PEERS_DIR/$peer_name/$peer_name.png erstellt."
}