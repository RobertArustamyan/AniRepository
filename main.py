import argparse
from Utilites.xss import detect_xss
from Utilites.toPDF import to_pdf
from dotenv import load_dotenv
import os

if __name__ == '__main__':
    load_dotenv()

    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")

    parser.add_argument("-x", "--xss", action="store_true",help="Enable XSS Scanning")
    parser.add_argument("-s", "--sql", action="store_true", help="Enable SQL Injection Scanning")
    parser.add_argument("-m", "--mitm", action="store_true", help="Enable MiTM Scanning")
    parser.add_argument("-d", "--ddos", action="store_true", help="Enable DDoS Scanning")
    parser.add_argument("-a", "--all", action="store_true", help="Enable All Scanning")

    parser.add_argument("url", type=str, help="URL of the website to scan")


    args = parser.parse_args()

    if args.xss:
        print("Running XSS scan...")
        detect_xss(args.url)
        to_pdf(fr'{os.getenv("PROJECT_PATH")}\Logs\xss_scan.log', fr'{os.getenv("PROJECT_PATH")}\LogsPDF\xss_scan.pdf')


    if args.sql:
        print("Running SQL Injection scan...")
        pass

    if args.mitm:
        print("Running MiTM scan...")
        pass

    if args.ddos:
        print("Running DDoS scan...")
        pass

    if args.all:
        print("Running all scans...")
        detect_xss()
        pass