import sqlite3
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from dotenv import load_dotenv
import os, re
from password_hasher import PasswordHasher
from security_gateway import Authenticator
import random

load_dotenv()
DB_PATH = os.getenv("DATABASE_URI")
SECRET_KEY = os.getenv("MUTUAL_SECRET_KEY")
hasher = PasswordHasher()
authenticator = Authenticator(DB_PATH, SECRET_KEY)
app = FastAPI(title="Hostel Canteen Central Node",
              dependencies=[Depends(authenticator.verify_frontend_app_authenticity)])

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS physical_qr_tokens (
                        token_id TEXT PRIMARY KEY,
                        card_status TEXT DEFAULT "AVAILABLE"
                   )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS trainee_assignments (
                        assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        token_id TEXT,
                        is_active INTEGER NOT NULL DEFAULT 1,
                        trainee_name TEXT,
                        trainee_desg TEXT,
                        course_start_date TEXT, --format(YYYY-MM-DD)
                        course_end_date TEXT, --format(YYYY-MM-DD)
                        meal_preference TEXT NOT NULL,
                        alloted_room_number TEXT DEFAULT "",
                        FOREIGN KEY (token_id) REFERENCES physical_qr_tokens (token_id)
                   )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS qr_scans (
                        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        assignment_id INTEGER,
                        scan_date TEXT, --format(YYYY-MM-DD)
                        scan_time TEXT, --format(HH:MM:SS)
                        FOREIGN KEY (assignment_id) REFERENCES trainee_assignments (assignment_id)
                   )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS settings (
                        key TEXT UNIQUE,
                        value TEXT
                   )''')
    
    conn.commit()
    conn.close()

init_db()

def is_time_in_slot(check_time: str, time_slot: str) -> bool:
    start_time, end_time = tuple(map(lambda x: datetime.strptime(x.strip(), "%H:%M:%S").time(), time_slot.split('-')))
    measurable_check_time = datetime.strptime(check_time.strip(), "%H:%M:%S").time()
    return (start_time <= measurable_check_time <= end_time)

ALLOWED_CONFIG_KEYS = {"breakfast_time_slot", "lunch_time_slot", "dinner_time_slot"} # more to be added later

@app.post("/api/configure-settings")
def configure_settings(key: str, value: str):
    if key not in ALLOWED_CONFIG_KEYS:
        raise HTTPException(
            status_code=400,
            detail=f"Modification of the configuration key '{key}' is restricted or invalid."
        )
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        return {
            "status": "success",
            "message": f"Configuration setting '{key}' successfully updated to '{value}'."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/api/generate-new-token")
def generate_new_token():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT token_id FROM physical_qr_tokens")
    existing_tokens = [row[0] for row in cursor.fetchall()]

    token_id = None
    while True:
        generated_code = random.randint(1000, 9999)
        code_hash = hasher.create_hash(str(generated_code))
        token_id = f"{generated_code}.{code_hash}"
        if token_id not in existing_tokens:
            break

    try:
        cursor.execute("INSERT INTO physical_qr_tokens (token_id) VALUES (?)", (token_id,))
        conn.commit()
        return {"status": "success", "token_id_no": generated_code, "final_token_id": token_id}

    # Check - Did the database refuse to insert the entry?
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/api/assign-token")
def assign_token_to_trainee(
    token_id: str,
    trainee_name: str,
    trainee_desg: str,
    course_start: str,
    course_end: str,
    meal_preference: str,
    alloted_room_number: str = ""
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT card_status FROM physical_qr_tokens WHERE token_id = ?", (token_id,))
    res = cursor.fetchone()

    # Check - Is the QR token a valid one (available physically)?
    if not res:
        conn.close()
        raise HTTPException(status_code=400, detail="Physical QR Token not found in stock inventory!")
    
    # Check - Is the QR already assigned to another trainee?
    elif res[0] != "AVAILABLE":
        conn.close()
        raise HTTPException(status_code=400, detail="The requested Physical QR is already assigned to a trainee!")

    cursor.execute("UPDATE physical_qr_tokens SET card_status = 'ASSIGNED' WHERE token_id = ?", (token_id,))
    try:
        cursor.execute('''INSERT INTO trainee_assignments (token_id, trainee_name, trainee_desg,
                       course_start_date, course_end_date, meal_preference, alloted_room_number)
                       VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                       (token_id, trainee_name, trainee_desg, course_start,
                        course_end, meal_preference, alloted_room_number)
                    )
        conn.commit()
        return {"status": "success", "token_id": token_id, "trainee_name": trainee_name,
                "trainee_desg": trainee_desg, "course_start": course_start,
                "course_end": course_end, "meal_preference": meal_preference, "alloted_room_number": alloted_room_number}
    
    # Check - Did the database refuse to insert the entry?
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/api/verify-token")
def verify_and_supply_data(token_id: str):
    parts = token_id.split('.')
    if (len(parts)!=2):
        raise HTTPException(status_code=404, detail="Invalid QR Code Scanned!")
    token_number, token_hash_code = parts

    if not hasher.check_password(token_number, token_hash_code):
        raise HTTPException(status_code=404, detail="Invalid QR Code scanned!")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT card_status FROM physical_qr_tokens WHERE token_id = ?", (token_id,))
    card_status = cursor.fetchone()

    # Check - Is the QR scanned a valid token?
    if not card_status:
        conn.close()
        raise HTTPException(status_code=404, detail="Invalid QR Code scanned!")
    
    cursor.execute('''
                   SELECT assignment_id, trainee_name, trainee_desg, course_start_date, course_end_date, meal_preference, alloted_room_number
                   FROM trainee_assignments
                   WHERE token_id = ? AND is_active = 1''', (token_id,))
    trainee_data = cursor.fetchone()

    # Check - Is the QR token assigned to a trainee?
    if not trainee_data:
        conn.close()
        raise HTTPException(status_code=404, detail="There is no trainee assigned to this Physical QR Token")
    
    assigment_id, name, desg, start_date, end_date, preference, room_no = trainee_data

    current_datetime = datetime.now()
    current_date = current_datetime.strftime("%Y-%m-%d")
    current_time = current_datetime.strftime("%H:%M:%S")

    # Check - Did the QR token expire for that trainee?
    if (datetime.strptime(end_date.strip(), "%Y-%m-%d").date() < current_datetime.date()):
        conn.close()
        raise HTTPException(status_code=403, detail="Physical QR Token expired for the trainee!")
        
    cursor.execute('''
                   SELECT * FROM settings
                   WHERE key = "breakfast_time_slot" OR key = "lunch_time_slot" OR key = "dinner_time_slot"''')
    time_slots = cursor.fetchall()

    # Check - Have the Meal Slot Timing Settings been initialized?
    if not time_slots:
        conn.close()
        raise HTTPException(status_code=422, detail="Meal Time Slot configuration data not found!")

    for slot_type, slot in time_slots:
        if is_time_in_slot(current_time, slot):
            cursor.execute("SELECT scan_time FROM qr_scans WHERE assignment_id = ? AND scan_date = ?",
                           (assigment_id, current_date))
            scan_times_today = cursor.fetchall()

            for scan_time in scan_times_today:

                # Check - Has the trainee already taken the meal receipt for that slot that day?
                if is_time_in_slot(scan_time[0], slot):
                    conn.close()
                    raise HTTPException(
                        status_code=403,
                        detail=f"The trainee has already received the meal receipt for {slot_type.upper().replace("_", " ")}!"
                    )
            try:  
                cursor.execute(
                    '''INSERT INTO qr_scans (assignment_id, scan_date, scan_time)
                    VALUES (?, ?, ?)''', (assigment_id, current_date, current_time)
                )
                conn.commit()
                return {"status": "success", "name": name, "desg": desg, "start_date": start_date,
                        "end_date": end_date, "meal_preference": preference, "room_no": room_no}
            
            # Check - Did the database refuse to insert the entry?
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
            finally:
                conn.close()
    
    # Check - Is it the correct time to scan the QR? (No meals right now)
    conn.close()
    raise HTTPException(status_code=403, detail="Not a valid meal slot! Try again later!")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("LISTEN_PORT")))