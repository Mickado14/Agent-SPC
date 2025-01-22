import os
import sys
import requests
from scapy.all import sniff, Ether, IP, ARP, ICMP, TCP, UDP
import time
import threading
from datetime import datetime

# Chemin du fichier de configuration
CONFIG_FILE = "../Agent-SPC/config/agent.conf"

cache = []  # Cache pour stocker les trames capturées
lock = threading.Lock()  # Verrou pour la gestion du cache

def load_config():
    """
    Charge les informations de configuration depuis le fichier agent.conf
    """
    if not os.path.exists(CONFIG_FILE):
        print("Erreur : Fichier de configuration introuvable. Veuillez exécuter le script d'installation.")
        exit(1)

    config = {}
    with open(CONFIG_FILE, 'r') as conf_file:
        for line in conf_file:
            key, value = line.strip().split("=")
            config[key] = value
    return config

def send_to_server(config):
    """
    Envoie les trames accumulées dans le cache au serveur
    """
    global cache
    url = f"http://{config['server_ip']}:{config['server_port']}/api/packet_logs"

    while True:
        time.sleep(10)  # Attendre 10 secondes
        with lock:
            if cache:
                payload = {"packets": cache}
                try:
                    response = requests.post(url, json=payload)
                    if response.status_code == 200:
                        print("Debug : Trames envoyées avec succès :", payload)
                    else:
                        print(f"Erreur serveur : {response.status_code} - {response.text}")
                except requests.RequestException as e:
                    print(f"Erreur d'envoi : {e}")
                finally:
                    cache = []  # Vider le cache
            else:
                print("Debug : Aucun paquet dans le cache à envoyer.")

def get_packet_type(packet):
    """
    Détermine le type de paquet en fonction des couches présentes
    """
    if ARP in packet:
        return "ARP"
    elif ICMP in packet:
        return "ICMP"
    elif TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif IP in packet:
        return "IP"
    else:
        return "UNKNOWN"

def process_packet(packet):
    """
    Traite une trame capturée et l'ajoute au cache
    """
    global cache
    try:
        source_ip = packet[IP].src if IP in packet else "UNKNOWN"
        destination_ip = packet[IP].dst if IP in packet else "UNKNOWN"
        source_mac = packet[Ether].src if Ether in packet else "UNKNOWN"
        destination_mac = packet[Ether].dst if Ether in packet else "UNKNOWN"
        packet_type = get_packet_type(packet)

        data = {
            "agent_name": config.get("agent_name", "unknown_agent"),
            "source_ip": source_ip,
            "source_mac": source_mac,
            "destination_ip": destination_ip,
            "destination_mac": destination_mac,
            "type": packet_type,
            "timestamp": datetime.now().isoformat(),
            "summary": packet.summary()
        }

        with lock:
            cache.append(data)

        if config.get("debug", "false").lower() == "true":
            print(f"Debug : Trame capturée : {data}")

    except Exception as e:
        print(f"Erreur lors du traitement d'une trame : {e}")

def capture_packets(config):
    """
    Capture les trames réseau et les traite
    """
    print("=== Démarrage de la capture des trames ===")
    print(f"Envoi des trames au serveur {config['server_ip']}:{config['server_port']}")
    sniff(prn=process_packet, store=0)  # Capture toutes les trames

def daemonize():
    """
    Transforme le processus en un démon pour tourner en arrière-plan
    """
    if os.fork():
        sys.exit()
    os.setsid()
    if os.fork():
        sys.exit()
    sys.stdout = open('/dev/null', 'w')
    sys.stderr = open('/dev/null', 'w')
    sys.stdin = open('/dev/null', 'r')

if __name__ == "__main__":
    config = load_config()

    if len(sys.argv) > 1 and sys.argv[1] == "--debug":
        config["debug"] = "true"
    else:
        daemonize()

    # Lancer le thread d'envoi
    sender_thread = threading.Thread(target=send_to_server, args=(config,))
    sender_thread.daemon = True
    sender_thread.start()

    # Commencer la capture des trames
    capture_packets(config)
