from scapy.all import ARP, Ether, srp
import logging
import json
import os


logger = logging.getLogger("CyberAudit")


def scan_network(network):
    """
    Découverte des machines actives sur un réseau

    Exemple:
    scan_network("192.168.1.0/24")
    """

    logger.info(
        f"Lancement du scan réseau : {network}"
    )

    # Création d'une requête ARP
    arp_request = ARP(
        pdst=network
    )

    # Création d'une trame Ethernet broadcast
    broadcast = Ether(
        dst="ff:ff:ff:ff:ff:ff"
    )

    packet = broadcast / arp_request


    # Envoi du paquet
    answered = srp(
        packet,
        timeout=3,
        verbose=False
    )[0]


    devices = []


    for sent, received in answered:

        device = {
            "ip": received.psrc,
            "mac": received.hwsrc
        }

        devices.append(device)


    logger.info(
        f"{len(devices)} machine(s) détectée(s)"
    )


    return devices

#pour la sauvegarde des résultats du scan dans un fichier JSON
def save_results(results):

    os.makedirs(
        "database",
        exist_ok=True
    )
    
    with open(
        "database/network_results.json",
        "w"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )

    logger.info(
        "Résultats sauvegardés dans network_results.json"
    )