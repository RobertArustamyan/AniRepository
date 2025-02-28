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
        logging.FileHandler("../Logs/sql_scan.log"),
        logging.StreamHandler()
    ]
)
# Load databases into variables from Databases/sql_payloads.json and Databases/sql_payloads_solutions.json
def load_sql_payloads_and_solutions():
    with open("../Databases/sql_payloads.json", "r", encoding='utf-8') as f:
        sql_payload = json.load(f)
    with open("../Databases/sql_payloads_solutions.json", "r", encoding='utf-8') as f:
        sql_payload_solutions = json.load(f)

    return {"payloads": sql_payload, "solutions": sql_payload_solutions}

def detect_sql(url, ):
    data = load_sql_payloads_and_solutions()
    payloads = data["payloads"]
    solutions = data["solutions"]



# For local tests
if __name__ == '__main__':
    detect_sql(url='http://altoro.testfire.net/login.jsp')

