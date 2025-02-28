import logging
import json
import requests
import logging
from bs4 import BeautifulSoup

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("../Logs/xss_scan.log"),
        logging.StreamHandler()
    ]
)
# Load databases into variables from Databases/xss_payloads.json and Databases/xss_payloads_solutions.json
def load_xss_payloads_and_solutions():
    with open("../Databases/xss_payloads.json", "r", encoding='utf-8') as f:
        xss_payload = json.load(f)
    with open("../Databases/xss_payloads_solutions.json", "r", encoding='utf-8') as f:
        xss_payload_solutions = json.load(f)

    return {"payloads": xss_payload, "solutions": xss_payload_solutions}

def detect_xss(url, test_params=['q','search','username','password','comment','query']):
    data = load_xss_payloads_and_solutions()
    payloads = data["payloads"]
    solutions = data["solutions"]

    logging.info(f"Scanning {url} for XSS vulnerabilities.")

    detected = False
    for param in test_params:
        for i in range(1, len(payloads) + 1):
            payload_info = payloads[f"{i}"]

            payload = payload_info['payload']
            payload_type = payload_info['type']

            test_url = f"{url}?{param}={payload}"
            response = requests.get(test_url)

            if payload in response.text:
                logging.warning(f"[XSS] Vulnerability detected at {test_url}")
                # Here I want to add in logging the solution for it.
                solution = solutions.get(payload_type, "No solution found.")
                logging.info(f"Solution for {payload_type}: {solution}")

                detected = True

    if not detected:
        logging.info(f"No XSS vulnerabilities found on {url}.")
        return False
    return True


# For local tests
if __name__ == '__main__':
    detect_xss('https://xss-game.appspot.com/level1/frame')

