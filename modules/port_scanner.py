import socket
import logging
import json
import os


logger = logging.getLogger("CyberAudit")


def scan_port(ip, port):
    """
    Vérifie si un port TCP est ouvert
    """

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)

        result = sock.connect_ex(
            (ip, port)
        )

        sock.close()


        if result == 0:
            return True

        else:
            return False


    except Exception as error:

        logger.error(error)

        return False



def port_scan(ip, ports):
    """
    Scan plusieurs ports sur une machine
    """

    logger.info(
        f"Scan des ports sur {ip}"
    )


    open_ports = []


    for port in ports:

        if scan_port(ip, port):

            open_ports.append(
                {
                    "port": port,
                    "state": "open"
                }
            )


    logger.info(
        f"{len(open_ports)} port(s) ouvert(s)"
    )


    return open_ports



def save_port_results(results):

    os.makedirs(
        "database",
        exist_ok=True
    )


    with open(
        "database/port_results.json",
        "w"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )


    logger.info(
        "Résultats ports sauvegardés"
    )
