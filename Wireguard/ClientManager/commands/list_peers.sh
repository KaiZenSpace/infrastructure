#!/bin/bash
# WireGuard Manager - Befehl zum Auflisten der Peers

# Kommando: list-peers - Alle Peers auflisten
list_peers() {
    check_wireguard
    check_config
    
    echo "=== WireGuard Peers ==="
    echo "NAME                PUBLIC KEY                                      IP-ADRESSE      VERBUNDEN      ZULETZT GESEHEN"
    echo "-------------------------------------------------------------------------------------------------------"
    
    # Aktuelle Verbindungen holen
    connections=$(get_connections)
    current_time=$(date +%s)
    
    # Peers aus der Konfigurationsdatei extrahieren
    while IFS= read -r line; do
        if [[ $line == \#* ]] && [[ $(wc -w <<< "$line") -eq 2 ]]; then
            # Peer-Name aus Kommentar extrahieren
            peer_name=$(echo "$line" | cut -d' ' -f2)
            
            # Die nächste Zeile sollte PublicKey sein
            read -r pubkey_line
            if [[ $pubkey_line == PublicKey* ]]; then
                pubkey=$(echo "$pubkey_line" | cut -d' ' -f3)
                
                # Die nächste Zeile überspringen (PresharedKey)
                read -r psk_line
                
                # Die nächste Zeile sollte AllowedIPs sein
                read -r allowed_ips_line
                ip=$(echo "$allowed_ips_line" | grep -oP 'AllowedIPs = \K[^/]+')
                
                # Verbindungsstatus prüfen
                is_connected="Nein"
                
                # Verbindungsstatus aus WireGuard direkt auslesen
                if connection_line=$(echo "$connections" | grep "$pubkey"); then
                    last_handshake=$(echo "$connection_line" | awk '{print $5}')
                    
                    if [ "$last_handshake" != "0" ]; then
                        # Zeitspanne seit dem letzten Handshake in Sekunden
                        seconds_since_handshake=$((current_time - last_handshake))
                        
                        # Wenn der letzte Handshake weniger als 3 Minuten her ist, gilt der Peer als verbunden
                        if [ "$seconds_since_handshake" -lt 180 ]; then
                            is_connected="Ja"
                            # Last-Seen aktualisieren mit aktueller Zeit
                            update_last_seen "$peer_name"
                        else
                            # Wenn nicht mehr verbunden, aber Handshake existiert, Last-Seen aktualisieren
                            update_last_seen "$peer_name" "$last_handshake"
                        fi
                    fi
                fi
                
                # Zuletzt gesehen Zeit holen
                last_seen=$(get_last_seen "$peer_name")
                last_seen_str=$(format_timestamp "$last_seen")
                
                printf "%-20s %-50s %-15s %-14s %-20s\n" "$peer_name" "$pubkey" "$ip" "$is_connected" "$last_seen_str"
            fi
        fi
    done < "$SERVER_CONF"
    
    # Anzahl der aktuellen Clients
    client_count=$(get_client_count)
    echo ""
    echo "Anzahl der Clients: $client_count"
    if [ "$MAX_CLIENTS" -gt 0 ]; then
        echo "Maximale Anzahl erlaubter Clients: $MAX_CLIENTS"
    else
        echo "Maximale Anzahl erlaubter Clients: Unbegrenzt"
    fi
}