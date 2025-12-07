import json
import sqlite3

DB_PATH = 'phishing.db'


def load_indicators_from_json(file_path='indicators.json'):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for item in data:
        cur.execute("""
                    INSERT
                    OR IGNORE INTO indicators 
            (type, value, risk_score, description, category, source)
            VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        item.get('type'),
                        item.get('value'),
                        item.get('risk_score', 1),
                        item.get('description', ''),
                        item.get('category', 'phishing'),
                        item.get('source', 'manual')
                    ))
    conn.commit()
    conn.close()
    print(f"Загружено {len(data)} индикаторов из indicators.json")


if __name__ == "__main__":
    load_indicators_from_json()