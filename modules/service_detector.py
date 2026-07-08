import socket
import logging
import json
import os


logger = logging.getLogger("CyberAudit")


# Dictionnaire des ports connus
SERVICES = {

    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP"

}


def detect_service(ip, port):
    """
    Identification du service
    """

    service = SERVICES.get(
        port,
        "Unknown"
    )

    banner = ""

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)


        sock.connect(
            (ip, port)
        )

        # Envoi d'une requête simple
        if port in [80,443]:

            sock.send(
                b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n"
            )


        response = sock.recv(
            1024
        )


        banner = response.decode(
            errors="ignore"
        )


        sock.close()


    except Exception:

        banner = "No banner"



    return {

        "port": port,
        "service": service,
        "banner": banner[:100]

    }



def detect_services(ip, ports):

    logger.info(
        f"Détection des services sur {ip}"
    )

    results = []


    for item in ports:

        port = item["port"]


        result = detect_service(
            ip,
            port
        )


        results.append(
            result
        )


    return results



def save_service_results(results):

    os.makedirs(
        "database",
        exist_ok=True
    )


    with open(
        "database/service_results.json",
        "w"
    ) as file:


        json.dump(
            results,
            file,
            indent=4
        )


    logger.info(
        "Résultats services sauvegardés"
    )