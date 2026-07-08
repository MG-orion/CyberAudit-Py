from modules.logger import setup_logger
from modules.network_scanner import scan_network, save_results
from modules.port_scanner import port_scan, save_port_results
from modules.service_detector import (detect_services,save_service_results)
from modules.vulnerability_checker import ( check_vulnerabilities,save_findings)


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
    save_results(results)


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

#ports
target = input(
    "Entrer l'IP à scanner : "
)

ports = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    443,
    445,
    3306,
    3389
]


port_results = port_scan(
    target,
    ports
)

#sauvegarde des résultats du scan de ports
save_port_results(
    port_results
)
#detection des services
service_results = detect_services(
    target,
    port_results
)

findings = check_vulnerabilities(
    service_results
)

save_findings(
    findings
)

save_service_results(
    service_results
)

#affichage des résultats
print("\nPorts ouverts :")
#vérification des vulnérabilités
print("\nAnalyse des vulnérabilités\n")

for finding in findings:

    print(f"""
Port : {finding['port']}
Service : {finding['service']}
Risque : {finding['risk']}

Problème :
{finding['issue']}

Recommandation :
{finding['recommendation']}
""")

for port in port_results:

    print(
        port
    )