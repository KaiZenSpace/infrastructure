#!/bin/bash
# WireGuard Manager - Befehl zum Entfernen eines Peers

# Kommando: remove-peer - Peer entfernen
remove_peer() {
    local peer_name="$1"
    local auto_delete="$2"  # Optional: "auto" falls automatisch gelöscht
    
    # Prüfen ob ein Name angegeben wurde
    if [ -z "$peer_name" ]; then
        error "Kein Peer-Name angegeben. Verwendung: wg-manager remove-peer <name>"
    fi
    
    check_wireguard
    check_config
    
    # Prüfen ob der Peer existiert
    if ! peer_exists "$peer_name"; then
        error "Kein Peer mit dem Namen '$peer_name' gefunden."
    fi
    
    # Public Key des Peers extrahieren
    pubkey=$(get_peer_pubkey "$peer_name")
    
    if [ -z "$pubkey" ]; then
        error "Konnte den Public Key für Peer '$peer_name' nicht finden."
    fi
    
    # Peer aus Konfigurationsdatei entfernen
    remove_peer_from_config "$peer_name"
    
    # Peer aus WireGuard entfernen
    remove_peer_from_wg "$pubkey"
    
    # Last-Seen-Eintrag löschen
    remove_last_seen_entry "$peer_name"
    
    echo "Peer '$peer_name' wurde erfolgreich entfernt."
    
    # Peer-Dateien entfernen
    remove_peer_files "$peer_name" "$auto_delete"
}