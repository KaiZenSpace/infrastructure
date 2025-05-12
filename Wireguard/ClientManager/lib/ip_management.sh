#!/bin/bash
# WireGuard Manager - IP-Management Funktionen
# Diese Datei enthält Funktionen zur Verwaltung von IP-Adressen

# Hilfsfunktion: Nächste freie IP-Adresse finden
find_next_ip() {
    # Alle bereits verwendeten IPs finden
    used_ips=$(grep -oP 'AllowedIPs = '"$IP_BASE"'\.\K[0-9]+' "$SERVER_CONF" | sort -n)
    
    # Wenn keine IPs gefunden wurden, mit 2 beginnen (da 1 der Server ist)
    if [ -z "$used_ips" ]; then
        echo "2"
        return
    fi
    
    # Nach Lücken in den verwendeten IPs suchen
    prev=1  # Start mit 1 (Server IP)
    for ip in $used_ips; do
        if [ $((ip - prev)) -gt 1 ]; then
            # Lücke gefunden - nächste freie IP ist prev+1
            echo $((prev + 1))
            return
        fi
        prev=$ip
    done
    
    # Keine Lücke gefunden - nächste freie IP ist die höchste verwendete + 1
    echo $((prev + 1))
}

# Hilfsfunktion: IP-Adresse eines Peers herausfinden
get_peer_ip() {
    local peer_name="$1"
    
    # IP-Adresse aus der Konfiguration extrahieren
    grep -A3 "# $peer_name$" "$SERVER_CONF" | grep "AllowedIPs" | grep -oP 'AllowedIPs = \K[^/]+'
}