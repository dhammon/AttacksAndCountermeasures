from future import annotations 
import json
import os 
import sqlite3 
from datetime import datetime 
import requests 
from faker import Faker 
from airflow.sdk import dag, task 

# ========================= 
# CONFIGURATION SECTION 
# ========================= 
DAG_ID = "etl_configurable" 
DATA_PREFIX = "users" # change to "users_secure" later if needed 
RAW_FILE = f"raw_{DATA_PREFIX}.json" 
ENRICHED_FILE = f"enriched_{DATA_PREFIX}.json" 
TRANSFORMED_FILE = f"transformed_{DATA_PREFIX}.json" 
DB_NAME = f"{DATA_PREFIX}.db" 
TABLE_NAME = f"{DATA_PREFIX}_etl" 
API_URL = "https://jsonplaceholder.typicode.com/users" 

# ========================= 
# PATH SETUP 
# ========================= 
AIRFLOW_HOME = os.environ.get("AIRFLOW_HOME", os.path.expanduser("~/airflow")) 
DATA_DIR = os.path.join(AIRFLOW_HOME, "data") 
DB_PATH = os.path.join(DATA_DIR, DB_NAME) 
fake = Faker() 

# ========================= 
# DAG DEFINITION 
# ========================= 
@dag( dag_id=DAG_ID, schedule=None, start_date=datetime(2026, 1, 1), catchup=False, tags=["etl", "demo", "configurable"], )
def etl_configurable(): 

    # ------------------------- 
    # Extract 
    # ------------------------- 
    @task 
    def extract() -> list[dict]: 
        os.makedirs(DATA_DIR, exist_ok=True) 
        resp = requests.get(API_URL, timeout=30) 
        resp.raise_for_status() 
        users = resp.json() 
        path = os.path.join(DATA_DIR, RAW_FILE) 
        with open(path, "w", encoding="utf-8") as f: 
            json.dump(users, f, indent=2) 
        return users 

    # ------------------------- 
    # Enrich 
    # ------------------------- 
    @task 
    def enrich(users: list[dict]) -> list[dict]: 
        os.makedirs(DATA_DIR, exist_ok=True) 
        enriched = [] 
        for user in users: 
            item = { 
                "source_id": user["id"], 
                "name": user["name"], 
                "username": user["username"], 
                "email": user["email"], 
                "phone": user["phone"], 
                "website": user["website"], 
                "company": user["company"]["name"], 
                "city": user["address"]["city"], 
                "street": user["address"]["street"], 
                "suite": user["address"]["suite"], 
                "zipcode": user["address"]["zipcode"], 
                "geo_lat": user["address"]["geo"]["lat"], 
                "geo_lng": user["address"]["geo"]["lng"], 
                # fake enrichment (non-sensitive baseline) 
                "fake_phone": fake.phone_number(), 
                "notes": f"Customer interaction recorded for {fake.name()}", 
            } 
            enriched.append(item) 
        path = os.path.join(DATA_DIR, ENRICHED_FILE) 
        with open(path, "w", encoding="utf-8") as f: 
            json.dump(enriched, f, indent=2) 
        return enriched 

    # ------------------------- 
    # Transform 
    # ------------------------- 
    @task 
    def transform(records: list[dict]) -> list[dict]: 
        os.makedirs(DATA_DIR, exist_ok=True) 
        transformed = [] 
        for r in records: 
            out = dict(r) 
            out["email_domain"] = r["email"].split("@")[-1].lower() if "@" in r["email"] else None 
            out["name_upper"] = r["name"].upper() 
            transformed.append(out) 
        path = os.path.join(DATA_DIR, TRANSFORMED_FILE) 
        with open(path, "w", encoding="utf-8") as f: 
            json.dump(transformed, f, indent=2) 
        return transformed 

    # ------------------------- 
    # Load 
    # ------------------------- 
    @task 
    def load(records: list[dict]) -> dict: 
        os.makedirs(DATA_DIR, exist_ok=True) 
        conn = sqlite3.connect(DB_PATH) 
        cur = conn.cursor() 
        cur.execute( 
            f""" 
            CREATE TABLE IF NOT EXISTS {TABLE_NAME} ( 
                source_id INTEGER, 
                name TEXT, 
                username TEXT, 
                email TEXT, 
                phone TEXT, 
                website TEXT, 
                company TEXT, 
                city TEXT, 
                street TEXT, 
                suite TEXT, 
                zipcode TEXT, 
                geo_lat TEXT, 
                geo_lng TEXT, 
                fake_phone TEXT, 
                notes TEXT, 
                email_domain TEXT, 
                name_upper TEXT, 
                loaded_at TEXT 
            ) 
            """ 
        ) 
        cur.execute(f"DELETE FROM {TABLE_NAME}") 
        now = datetime.utcnow().isoformat() 
        cur.executemany( 
            f""" 
            INSERT INTO {TABLE_NAME} ( 
                source_id, name, username, email, phone, website, company, 
                city, street, suite, zipcode, geo_lat, geo_lng, 
                fake_phone, notes, email_domain, name_upper, loaded_at 
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
            """, 
            [ 
                ( 
                    r.get("source_id"), 
                    r.get("name"), 
                    r.get("username"), 
                    r.get("email"), 
                    r.get("phone"), 
                    r.get("website"), 
                    r.get("company"), 
                    r.get("city"), 
                    r.get("street"), 
                    r.get("suite"), 
                    r.get("zipcode"), 
                    r.get("geo_lat"), 
                    r.get("geo_lng"), 
                    r.get("fake_phone"), 
                    r.get("notes"), 
                    r.get("email_domain"), 
                    r.get("name_upper"), 
                    now, 
                ) 
                for r in records 
            ], 
        ) 
        conn.commit() 
        row_count = cur.execute(f"SELECT COUNT(*) FROM {TABLE_NAME}").fetchone()[0] 
        conn.close() 
        return {"db_path": DB_PATH, "rows_loaded": row_count} 

    # ------------------------- 
    # Pipeline Wiring 
    # ------------------------- 
    load(transform(enrich(extract()))) 

etl_configurable_dag = etl_configurable() 
