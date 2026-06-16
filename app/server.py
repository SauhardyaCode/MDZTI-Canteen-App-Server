import psycopg2
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from any client machine
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ALLOWED_CONFIG_KEYS = {"breakfast_time_slot", "lunch_time_slot", "dinner_time_slot"} # more to be added later

def is_time_in_slot(check_time: str, time_slot: str) -> bool:
    start_time, end_time = tuple(map(lambda x: datetime.strptime(x.strip(), "%H:%M:%S").time(), time_slot.split('-')))
    measurable_check_time = datetime.strptime(check_time.strip(), "%H:%M:%S").time()
    return (start_time <= measurable_check_time <= end_time)

def get_current_ist_datetime() -> datetime:
    aware_current_time_utc = datetime.now(timezone.utc)
    aware_current_time_ist = aware_current_time_utc + timedelta(hours=5, minutes=30)
    current_time_ist = aware_current_time_ist.replace(tzinfo=None)
    return current_time_ist

def close_connection_raise_error(
        conn: psycopg2.extensions.connection,
        cursor: psycopg2.extensions.cursor,
        status_code: int = 200,
        error_message: str = None
    ) -> None:
    cursor.close()
    conn.close()
    if status_code != 200:
        raise HTTPException(status_code=status_code, detail=error_message)


def init_db():
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS physical_qr_tokens (
                        token_number INTEGER PRIMARY KEY,
                        token_id TEXT,
                        card_status TEXT DEFAULT 'AVAILABLE'
                   )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS trainee_assignments (
                        assignment_id SERIAL PRIMARY KEY,
                        token_id TEXT,
                        is_active INTEGER NOT NULL DEFAULT 1,
                        trainee_name TEXT,
                        trainee_desg TEXT,
                        course_start_date TEXT, --format(YYYY-MM-DD)
                        course_end_date TEXT, --format(YYYY-MM-DD)
                        meal_preference TEXT NOT NULL,
                        FOREIGN KEY (token_id) REFERENCES physical_qr_tokens (token_id)
                   )''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS qr_scans (
                        scan_id BIGSERIAL PRIMARY KEY,
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
    close_connection_raise_error(conn, cursor)

init_db()


def _verify_and_supply_data(
        conn: psycopg2.extensions.connection,
        cursor: psycopg2.extensions.cursor,
        token_id: str,
        token_number: int
    ) -> dict[str, int | str]:
    cursor.execute('''
                   SELECT assignment_id, trainee_name, trainee_desg, course_start_date, course_end_date, meal_preference
                   FROM trainee_assignments
                   WHERE token_id = %s AND is_active = 1''', (token_id,))
    trainee_data = cursor.fetchone()

    # Check - Is the QR token assigned to a trainee?
    if not trainee_data:
        close_connection_raise_error(conn, cursor, 404, "There is no trainee assigned to this Physical QR Token")
    else:
        assigment_id, name, desg, start_date, end_date, preference = trainee_data

    current_datetime = get_current_ist_datetime()
    current_date = current_datetime.strftime("%Y-%m-%d")
    current_time = current_datetime.strftime("%H:%M:%S")

    # Check - Did the QR token expire for that trainee?
    if (datetime.strptime(end_date.strip(), "%Y-%m-%d").date() < current_datetime.date()):
        close_connection_raise_error(conn, cursor, 403, "Physical QR Token expired for the trainee!")
        
    cursor.execute('''
                   SELECT key, value FROM settings
                   WHERE key IN ('breakfast_time_slot', 'lunch_time_slot', 'dinner_time_slot')
                   ''')
    time_slots = cursor.fetchall()

    # Check - Have the Meal Slot Timing Settings been initialized?
    if not time_slots:
        close_connection_raise_error(conn, cursor, 422, "Meal Time Slot configuration data not found!")

    for slot_type, slot in time_slots:
        if is_time_in_slot(current_time, slot):
            cursor.execute("SELECT scan_time FROM qr_scans WHERE assignment_id = %s AND scan_date = %s",
                           (assigment_id, current_date))
            scan_times_today = [res[0] for res in cursor.fetchall()]

            for scan_time in scan_times_today:

                # Check - Has the trainee already taken the meal receipt for that slot that day?
                if is_time_in_slot(scan_time, slot):
                    close_connection_raise_error(
                        conn, cursor, 403,
                        f"The trainee has already received the meal receipt for {slot_type.upper().replace("_", " ")}!" 
                    )
            try:  
                cursor.execute(
                    '''INSERT INTO qr_scans (assignment_id, scan_date, scan_time)
                    VALUES (%s, %s, %s)''', (assigment_id, current_date, current_time)
                )
                conn.commit()
                return {"status": "success", "token_number": token_number, "trainee_name": name,
                        "trainee_desg": desg, "course_start_date": start_date,
                        "course_end_date": end_date, "meal_preference": preference}
            
            # Check - Did the database refuse to insert the entry?
            except Exception as e:
                conn.rollback()
                raise HTTPException(status_code=500, detail=str(e))
            finally:
                close_connection_raise_error(conn, cursor)
    
    # Check - Is it the correct time to scan the QR? (No meals right now)
    close_connection_raise_error(conn, cursor, 403, "Not a valid meal slot! Try again later!")


@app.get("/")
def home_root():
    return {"message": "The Canteen Backend is fully live and online!"}

@app.post("/api/configure-settings")
def configure_settings(key: str, value: str):
    if key not in ALLOWED_CONFIG_KEYS:
        raise HTTPException(
            status_code=400,
            detail=f"Modification of the configuration key '{key}' is restricted or invalid."
        )
        
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        query = """
                INSERT INTO settings (key, value)
                VALUES (%s, %s)
                ON CONFLICT
                DO UPDATE SET value = EXCLUDED.value
        """
        cursor.execute(query, (key, value))
        conn.commit()
        return {
            "status": "success",
            "message": f"Configuration setting '{key}' successfully updated to '{value}'."
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        close_connection_raise_error(conn, cursor)

@app.post("/api/generate-new-token")
def generate_new_token():
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT token_number FROM physical_qr_tokens")
    existing_token_nos = sorted([row[0] for row in cursor.fetchall()])

    new_token_no = 1
    for token_number in existing_token_nos:
        if token_number == new_token_no:
            new_token_no += 1
        else:
            break

    new_token_hash = hasher.create_hash(str(new_token_no))
    new_token_id = f"{new_token_no}.{new_token_hash}"

    try:
        cursor.execute("""INSERT INTO physical_qr_tokens (token_number, token_id)
                       VALUES (%s, %s)""", (new_token_no, new_token_id))
        conn.commit()
        return {"status": "success", "token_id_no": new_token_no, "final_token_id": new_token_id}

    # Check - Did the database refuse to insert the entry?
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        close_connection_raise_error(conn, cursor)

@app.post("/api/assign-token")
def assign_token_to_trainee(
    token_number: str,
    trainee_name: str,
    trainee_desg: str,
    course_start: str,
    course_end: str,
    meal_preference: str,
):
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT token_id, card_status FROM physical_qr_tokens WHERE token_number = %s", (token_number,))
    res = cursor.fetchone()

    # Check - Is the QR token a valid one (available physically)?
    if not res:
        close_connection_raise_error(conn, cursor, 400, "Physical QR Token not found in stock inventory!")
    else:
        token_id, card_status = res

    # Check - Is the QR already assigned to another trainee?
    if card_status != "AVAILABLE":
        close_connection_raise_error(conn, cursor, 400, "The requested Physical QR is already assigned to a trainee!")

    cursor.execute("UPDATE physical_qr_tokens SET card_status = 'ASSIGNED' WHERE token_number = %s", (token_number,))
    try:
        cursor.execute('''INSERT INTO trainee_assignments (token_id, trainee_name, trainee_desg,
                       course_start_date, course_end_date, meal_preference)
                       VALUES (%s, %s, %s, %s, %s, %s)''', 
                       (token_id, trainee_name, trainee_desg, course_start,
                        course_end, meal_preference)
                    )
        conn.commit()
        return {"status": "success", "token_id": token_id, "trainee_name": trainee_name,
                "trainee_desg": trainee_desg, "course_start": course_start,
                "course_end": course_end, "meal_preference": meal_preference}
    
    # Check - Did the database refuse to insert the entry?
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        close_connection_raise_error(conn, cursor)

@app.post("/api/verify-token")
def verify_scanned_token(token_id: str):
    parts = token_id.split('.')
    if (len(parts)!=2):
        raise HTTPException(status_code=404, detail="Invalid QR Code Scanned! (Invalid Format)")
    token_number, token_hash_code = parts

    if not hasher.check_password(token_number, token_hash_code):
        raise HTTPException(status_code=404, detail="Invalid QR Code scanned! (Invalid Hash)")

    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT 1 FROM physical_qr_tokens WHERE token_id = %s", (token_id,))
    res = cursor.fetchone()

    # Check - Is the QR scanned a valid token?
    if not res:
        close_connection_raise_error(conn, cursor, 404, "Invalid QR Code scanned! (Invalid Token Number)")
    
    return _verify_and_supply_data(conn, cursor, token_id=token_id, token_number=token_number)

@app.post("/api/verify-token-manual")
def verify_typed_token(token_number: int):
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT token_id FROM physical_qr_tokens WHERE token_number = %s", (token_number,))
    res = cursor.fetchone()

    # Check - Is the QR scanned a valid token?
    if not res:
        close_connection_raise_error(conn, cursor, 404, "Invalid Token Number (Not Registered)")
    else:
        token_id = res[0]
    
    return _verify_and_supply_data(conn, cursor, token_id=token_id, token_number=token_number)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("LISTEN_PORT")))