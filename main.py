from modules.logger import setup_logger


def main():
    logger = setup_logger()
    logger.info(
        "Démarrage de CyberAudit-Py"
    )
    print(
        """
        ==========================
          CyberAudit-Py
          Security Scanner
        ==========================
        """
    )


if __name__ == "__main__":
    main()
