# Multi-Protocol-Brutefox

## Description:
A multi-protocol brute-force attack tool that supports SSH, FTP, HTTP Basic Authentication, and Telnet protocols. The tool is designed to conduct brute-force attacks efficiently using multi-threading, with enhanced logging features, target verification, and customizable configurations.

## Features:
Protocol Support: Brute-force capabilities for SSH, FTP, HTTP Basic Auth, and Telnet.
Multi-threading: Speed up the attack process by using multiple threads for simultaneous attempts.
Target Verification: Checks if the target service (e.g., SSH, FTP) is reachable before starting the brute-force process.
Logging Enhancements:
Verbose Mode: Detailed logs for every attempt.
Logs success and failure attempts, errors, and runtime performance.
Customizable Settings:
Custom time delays between attempts to avoid detection.
User-defined number of threads to control concurrency.
Option to choose a protocol (SSH, FTP, HTTP, Telnet) for the brute-force attack.
Real-Time Progress Monitoring: Prints live status updates of attempts and attack progress.
Target Service Reachability Check: Verifies if the target IP and port are open and accessible before attempting brute-force attacks.
Error Handling: Graceful exit and logging of errors for easier debugging.

## Installation:
1. Clone the repository:
```bash
  git clone https://github.com/your-username/Multi-Protocol-Brutefox.git
  cd Multi-Protocol-Brutefox
```
2. Install required dependencies: Make sure you have Python 3.6+ installed, then use pip to install the required dependencies:
```bash
  pip install -r requirements.txt
```
3. Usage: After installing the dependencies, you can run the script as follows:
```bash
  python3 portbrutefox.py
```
## Notes:
Ensure that you have legal authorization to conduct security testing on the target system.
This tool is intended for educational and research purposes only. Unauthorized access to systems is illegal and unethical.

## Author:
Harsh Sandigada - @Harsh2154

