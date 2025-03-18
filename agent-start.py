import os
import requests
from scapy.all import sniff, ARP
import time
import threading
from datetime import datetime
import urllib3
import sys
import subprocess

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    url = f"https://{config['server_ip']}:{config['server_port']}/api/packet_logs"
    agent_name = config.get("agent_name", "unknown_agent")  # Récupère le nom de l'agent

    while True:
        time.sleep(10)  # Attendre 10 secondes
        with lock:
            if cache:
                # Ajout du nom de l'agent à chaque paquet avant l'envoi
                payload = {
                    "packets": cache
                }
                try:
                    response = requests.post(url, json=payload, verify=False)
                    if response.status_code == 200:
                        print(f"{len(cache)} trames ARP envoyées au serveur.")
                    else:
                        print(f"Erreur serveur : {response.status_code} - {response.text}")
                except requests.RequestException as e:
                    print(f"Erreur d'envoi : {e}")
                finally:
                    cache = []  # Vider le cache


def process_packet(packet):
    """
    Traite une trame capturée et l'ajoute au cache si elle est de type ARP
    """
    global cache
    config = load_config()
    agent_name = config.get("agent_name", "unknown_agent")  # Récupérer le nom de l'agent

    try:
        # Vérifiez que le paquet est de type ARP
        if ARP in packet:
            arp_type = "Request" if packet.op == 1 else "Reply" if packet.op == 2 else "Unknown"

            data = {
                "agent_name": agent_name,  # Nom de l'agent placé en premier
                "source_ip": packet.psrc if hasattr(packet, "psrc") else None,
                "source_mac": packet.hwsrc if hasattr(packet, "hwsrc") else None,
                "destination_ip": packet.pdst if hasattr(packet, "pdst") else None,
                "destination_mac": packet.hwdst if hasattr(packet, "hwdst") else None,
                "type": "ARP",  # Identification correcte du type
                "arp_type": arp_type,  # Ajout du type ARP
                "timestamp": datetime.now().isoformat(),
                "summary": packet.summary()  # Résumé lisible de la trame
            }

            with lock:
                cache.append(data)
    except Exception as e:
        print(f"Erreur lors du traitement d'une trame : {e}")


def capture_packets(config):
    """
    Capture uniquement les trames ARP et les traite
    """
    print("=== Démarrage de la capture des trames ARP ===")
    print(f"Envoi des trames ARP au serveur {config['server_ip']}:{config['server_port']}")
    # Capture uniquement les trames ARP
    sniff(prn=process_packet, store=0, filter="arp")


def run_in_deamon():
    """
    Exécute le script en mode daemon en arrière-plan
    """
    config = load_config()

    # Lancer le thread d'envoi
    sender_thread = threading.Thread(target=send_to_server, args=(config,))
    sender_thread.daemon = True
    sender_thread.start()

    # Commencer la capture des trames ARP
    capture_packets(config)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: script.py [-deamon|-debug]")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "-debug":
        # Lancer le script normalement avec le mode debug
        config = load_config()

        # Lancer le thread d'envoi
        sender_thread = threading.Thread(target=send_to_server, args=(config,))
        sender_thread.daemon = True
        sender_thread.start()

        # Commencer la capture des trames ARP
        capture_packets(config)

    elif mode == "-deamon":
        # Exécuter le script en mode daemon en arrière-plan avec subprocess
        subprocess.Popen([sys.executable, __file__, "-debug"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("Le script fonctionne en mode daemon en arrière-plan.")
        sys.exit(0)

    else:
        print("Usage: script.py [-deamon|-debug]")
        sys.exit(1)
