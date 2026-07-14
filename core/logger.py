import logging
import sys
from threading import Lock
from colorama import Fore, Style, init

init(autoreset=True)

class HorizonLogger:
    _lock = Lock()
    def __init__(self, name: str = "Horizon"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s', '%H:%M:%S')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def info(self, message: str) -> None:
        with self._lock:
            print(f"{Fore.BLUE}[*] INFO: {message}{Style.RESET_ALL}")

    def success(self, message: str) -> None:
        with self._lock:
            print(f"{Fore.GREEN}[+] SUCCESS: {message}{Style.RESET_ALL}")

    def warn(self, message: str) -> None:
        with self._lock:
            print(f"{Fore.YELLOW}[!] WARN: {message}{Style.RESET_ALL}")

    def critical(self, message: str) -> None:
        with self._lock:
            print(f"{Fore.RED}[x] CRITICAL: {message}{Style.RESET_ALL}")

logger = HorizonLogger()
