from scapy.all import ARP, Ether, srp
import logging


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
