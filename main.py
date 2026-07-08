from modules.logger import setup_logger
from modules.network_scanner import scan_network


def main():

    setup_logger()


    print("""
    ==========================
       CyberAudit-Py
    ==========================
    """)


    network=input(
        "Entrer le réseau à scanner : "
    )


    results = scan_network(network)


    print("\nMachines détectées :")


    for device in results:

        print(
            f"""
            IP  : {device['ip']}
            MAC : {device['mac']}
            """
        )



if __name__ == "__main__":
    main()
