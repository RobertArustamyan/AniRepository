import scapy.all as scapy
import re
import os
import numpy as np
import mysql.connector
from fpdf import FPDF
import requests
from Crypto.Cipher import AES
import base64
import hashlib
from sklearn.ensemble import IsolationForest
import argparse
import getpass
import logging
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(filename='vulnerability_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ✅ Attack detected tracker
attack_detected = {"DDoS": 0, "MiTM": 0, "XSS": 0, "SQLi": 0}

# ✅ Encryption function (AES)
def encrypt_data(data):
    key = hashlib.sha256(os.getenv("ENCRYPTION_KEY", "your_secret_key").encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_data(data):
    decoded = base64.b64decode(data)
    nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
    key = hashlib.sha256(os.getenv("ENCRYPTION_KEY", "your_secret_key").encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode()

# ✅ MySQL connection and encrypted database
try:
    db = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", "HelloWorld123+"),
        database=os.getenv("DB_NAME", "mysql"),
        charset="utf8mb4",
        collation="utf8mb4_general_ci"
    )
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INT AUTO_INCREMENT PRIMARY KEY,
            attack_type VARCHAR(10),
            src_ip VARCHAR(20),
            details TEXT,
            solution TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
except mysql.connector.Error as err:
    logging.error(f"Database error: {err}")

# ✅ Machine Learning model for SQLi detection
normal_queries = np.array([[10, 1], [12, 0], [14, 2], [20, 1]])
clf = IsolationForest(contamination=0.2)
clf.fit(normal_queries)

# 🔹 Load payloads and solutions from files
def load_payloads_and_solutions(attack_type):
    payloads_file = f"{attack_type}_payloads.txt"
    solutions_file = f"{attack_type}_payloads_solutions.txt"
    
    try:
        with open(payloads_file, "r") as f:
            payloads = f.read().splitlines()
        
        with open(solutions_file, "r") as f:
            solutions = f.read().splitlines()
        
        return payloads, solutions
    except FileNotFoundError:
        logging.error(f"Payload or solution file not found for {attack_type}")
        return [], []

# 🔹 SQLi detection function
def detect_sqli(query, src_ip):
    payloads, solutions = load_payloads_and_solutions("sqli")

    for i, payload in enumerate(payloads):
        if payload in query:
            log_attack("SQLi", src_ip, query, solutions[i])
            return True

    symbol_count = sum(1 for c in query if c in ["'", '"', "=", ";", "*"])
    new_query = np.array([[len(query), symbol_count]])

    if clf.predict(new_query) == -1:
        log_attack("SQLi", src_ip, "ML detected anomaly", "Solution: Use parameterized queries to prevent SQL Injection.")
        return True

    return False

# 🔹 XSS detection function
def detect_xss(payload, src_ip):
    payloads, solutions = load_payloads_and_solutions("xss")
    
    for i, p in enumerate(payloads):
        if p in payload:
            log_attack("XSS", src_ip, payload, solutions[i])
            return True

    return False

# 🔹 DDoS detection function
def detect_ddos(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        if packet.haslayer(scapy.UDP):
            log_attack("DDoS", src_ip, "UDP Flood detected", "Solution: Implement rate limiting and firewall rules.")
        elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 2:
            log_attack("DDoS", src_ip, "SYN Flood detected", "Solution: Implement SYN cookies and firewall rules.")

# 🔹 MiTM detection function
def detect_mitm(packet):
    if packet.haslayer(scapy.Raw):
        raw_data = packet[scapy.Raw].load
        if b"HTTP" in raw_data:
            src_ip = packet[scapy.IP].src
            log_attack("MiTM", src_ip, "Detected HTTP downgrade attack", "Solution: Use HTTPS exclusively.")
        elif b"SSL" in raw_data or b"TLS" in raw_data:
            src_ip = packet[scapy.IP].src
            log_attack("MiTM", src_ip, "Detected SSL/TLS stripping", "Solution: Enforce strict HTTPS usage and consider using HSTS.")

# 🔹 Log the detected attack in database with encryption
def log_attack(attack_type, src_ip, details, solution):
    try:
        encrypted_details = encrypt_data(details)
        encrypted_solution = encrypt_data(solution)
        
        cursor.execute("INSERT INTO vulnerabilities (attack_type, src_ip, details, solution) VALUES (%s, %s, %s, %s)",
                       (attack_type, src_ip, encrypted_details, encrypted_solution))
        db.commit()
        attack_detected[attack_type] += 1
    except Exception as err:
        logging.error(f"Error logging attack: {err}")

# 🔹 Packet analysis function (only process HTTP traffic)
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            # Only process HTTP traffic (port 80)
            if packet[scapy.TCP].dport == 80 or packet[scapy.TCP].sport == 80:
                raw_data = packet[scapy.Raw].load.decode(errors='ignore')
                
                # Log raw packet data for debugging
                logging.info(f"Raw Data: {raw_data[:100]}...")
                
                # Check for potential XSS or SQLi payloads
                if detect_xss(raw_data, src_ip):
                    return
                if detect_sqli(raw_data, src_ip):
                    return
    
    detect_ddos(packet)
    detect_mitm(packet)

# 🔹 Start sniffing
def start_sniffing():
    print("[INFO] Starting scanning...")
    scapy.sniff(prn=packet_callback, store=0)

# 🔹 Generate PDF report
def generate_pdf():
    pdf = FPDF()
    pdf.set_font("Arial", size=12)
    pdf.add_page()
    pdf.cell(200, 10, "Security Vulnerability Report", ln=True, align="C")

    cursor.execute("SELECT * FROM vulnerabilities")
    results = cursor.fetchall()

    for row in results:
        decrypted_details = decrypt_data(row[3])
        decrypted_solution = decrypt_data(row[4])
        pdf.cell(200, 10, f"ID: {row[0]} | Type: {row[1]} | IP: {row[2]} | Details: {decrypted_details} | Solution: {decrypted_solution}", ln=True)

    pdf.output("Vulnerability_Report.pdf")
    print("[INFO] Report created: Vulnerability_Report.pdf")

# 🔹 Check admin access
def check_admin_access():
    password = getpass.getpass("Enter admin password: ")
    if password == "admin123":  # Replace with a secure password management system
        return True
    return False

# 🔹 Main command line interface
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("--scan", action="store_true", help="Start scanning for vulnerabilities")
    parser.add_argument("--url", type=str, help="URL of the website to scan", required=True)

    args = parser.parse_args()

    if args.admin:
        if check_admin_access():
            print("Admin access granted.")
            # Add admin-specific functionality here
        else:
            print("Incorrect password. Access denied.")
            exit()
    
    if args.scan:
        start_sniffing()
    if args.report:
        generate_pdf()
