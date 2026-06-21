from typing import Dict, Union, Any, List
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime, timezone, timedelta, date as DATE
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
from password_hasher import PasswordHasher
from security_gateway import Authenticator

load_dotenv()
DB_PATH = os.getenv("DATABASE_URI")
SECRET_KEY = os.getenv("MUTUAL_SECRET_KEY")

class UtilityFunctions:
    def initialize_database(self):
        conn = psycopg2.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS physical_qr_tokens (
                            token_number INTEGER PRIMARY KEY,
                            token_id TEXT UNIQUE,
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
        
        # keys (breakfast_time_slot, lunch_time_slot, dinner_time_slot, last_updated, last_polled, only_veg_days)
        cursor.execute('''CREATE TABLE IF NOT EXISTS settings (
                            key TEXT UNIQUE,
                            value TEXT
                    )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS special_config (
                            exception_id BIGSERIAL PRIMARY KEY,
                            token_number INTEGER,
                            from_date TEXT, --format(YYYY-MM-DD)
                            to_date TEXT, --format(YYYY-MM-DD),
                            breakfast_time_slot TEXT DEFAULT NULL,
                            lunch_time_slot TEXT DEFAULT NULL,
                            dinner_time_slot TEXT DEFAULT NULL,
                            is_suspended BOOLEAN DEFAULT NULL
                    )''')
        
        conn.commit()
        self.close_connection_raise_error(conn, cursor)

    def is_time_in_slot(self, check_time: str, time_slot: str) -> bool:
        start_time, end_time = tuple(map(lambda x: datetime.strptime(x.strip(), "%H:%M:%S").time(), time_slot.split('-')))
        measurable_check_time = datetime.strptime(check_time.strip(), "%H:%M:%S").time()
        return (start_time <= measurable_check_time <= end_time)

    def get_current_ist_datetime(self) -> datetime:
        aware_current_time_utc = datetime.now(timezone.utc)
        aware_current_time_ist = aware_current_time_utc + timedelta(hours=5, minutes=30)
        current_time_ist = aware_current_time_ist.replace(tzinfo=None)
        return current_time_ist

    def close_connection_raise_error(
            self,
            conn: psycopg2.extensions.connection,
            cursor: psycopg2.extensions.cursor,
            status_code: int = 200,
            error_message: str = None
        ) -> None:
        cursor.close()
        conn.close()
        if status_code != 200:
            raise HTTPException(status_code=status_code, detail=error_message)
    
    def invalidate_client_cache(self, cursor: psycopg2.extensions.cursor) -> None:
        cursor.execute(
            """
                INSERT INTO settings (key, value)
                VALUES ('last_updated', %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            (self.get_current_ist_datetime().isoformat(),)
        )
    
    def verify_token_and_supply_data(
        self,
        conn: psycopg2.extensions.connection,
        cursor: psycopg2.extensions.cursor,
        token_id: str,
        token_number: int
    ) -> Dict[str, Union[int, str]]:
        cursor.execute('''
                    SELECT assignment_id, trainee_name, trainee_desg, course_start_date, course_end_date, meal_preference
                    FROM trainee_assignments
                    WHERE token_id = %s AND is_active = 1
                    ''', (token_id,)
                    )
        trainee_data = cursor.fetchone()
        warning = None

        # Check - Is the QR token assigned to a trainee?
        if not trainee_data:
            self.close_connection_raise_error(conn, cursor, 404, "There is no trainee assigned to this Physical QR Token")
        else:
            assigment_id, name, desg, start_date, end_date, preference = trainee_data
        
        current_datetime = self.get_current_ist_datetime()
        current_date = current_datetime.strftime("%Y-%m-%d")
        current_time = current_datetime.strftime("%H:%M:%S")

        # Check - Did the QR token expire for that trainee?
        if (datetime.strptime(end_date.strip(), "%Y-%m-%d").date() < current_datetime.date()):
            self.close_connection_raise_error(conn, cursor, 403, "Physical QR Token expired for the trainee!")

        cursor.execute("SELECT key, value FROM settings WHERE key LIKE '%_time_slot' OR key = 'only_veg_days'")
        settings: Dict[str, str] = {key:value for (key, value) in cursor.fetchall()}

        time_slot_keys = ("breakfast_time_slot", "lunch_time_slot", "dinner_time_slot")

        # Check - Have the Meal Slot Timing Settings been initialized?
        if not all([slot in settings for slot in time_slot_keys]):
            self.close_connection_raise_error(conn, cursor, 422, "Meal Time Slot configuration data not found!")

        active_breakfast_slot = settings.get(time_slot_keys[0])
        active_lunch_slot = settings.get(time_slot_keys[1])
        active_dinner_slot = settings.get(time_slot_keys[2])
        only_veg_days = settings.get("only_veg_days")

        if only_veg_days and only_veg_days.strip():
            only_veg_days_arr = [day.strip().title() for day in only_veg_days.split(',') if day.strip()]
            if current_datetime.strftime("%a") in only_veg_days_arr:
                preference = "VEG (same for all today)"
        else:
            warning = "Weekdays for only VEG not set in setting yet!"

        cursor.execute('''
                    SELECT breakfast_time_slot, lunch_time_slot, dinner_time_slot, is_suspended
                    FROM special_config
                    WHERE token_number = %s AND %s BETWEEN from_date AND to_date
                    ORDER BY exception_id DESC LIMIT 1
                    ''', (token_number, current_date)
                    )
        active_exception = cursor.fetchone()

        if active_exception:
            custom_breakfast_slot, custom_lunch_slot, custom_dinner_slot, is_suspended = active_exception

            # Check - Is that trainee suspended from meals for today (due to vacation etc.)?
            if is_suspended:
                self.close_connection_raise_error(conn, cursor, 403, f"Token No. ({token_number}) is suspended from meals today!")

            active_breakfast_slot = custom_breakfast_slot or active_breakfast_slot
            active_lunch_slot = custom_lunch_slot or active_lunch_slot
            active_dinner_slot = custom_dinner_slot or active_dinner_slot
        
        time_slot_names = ("Breakfast", "Lunch", "Dinner")
        active_time_slots = (active_breakfast_slot, active_lunch_slot, active_dinner_slot)
        
        matched_slot_name = None
        matched_slot_value = None

        for slot_type, slot in zip(time_slot_names, active_time_slots):
            if self.is_time_in_slot(current_time, slot):
                matched_slot_name = slot_type
                matched_slot_value = slot
                break
        
        if not matched_slot_name:
            # Check - Is it the correct time to scan the QR? (No meals right now)
            self.close_connection_raise_error(conn, cursor, 403, "Not a valid meal slot! Try again later!")
        
        cursor.execute(
            "SELECT scan_time FROM qr_scans WHERE assignment_id = %s AND scan_date = %s",
            (assigment_id, current_date)
        )
        scan_times_today = [res[0] for res in cursor.fetchall()]

        for scan_time in scan_times_today:
            # Check - Has the trainee already taken the meal receipt for that slot that day?
            if self.is_time_in_slot(scan_time, matched_slot_value):
                self.close_connection_raise_error(
                    conn, cursor, 403,
                    f"The trainee has already taken the meal for {matched_slot_name.upper()}!" 
                )

        cursor.execute(
            '''INSERT INTO qr_scans (assignment_id, scan_date, scan_time)
            VALUES (%s, %s, %s)''', (assigment_id, current_date, current_time)
        )
        conn.commit()
        self.close_connection_raise_error(conn, cursor)

        return {"status": "success", "token_number": token_number, "trainee_name": name,
                "trainee_desg": desg, "course_start_date": start_date,
                "course_end_date": end_date, "meal_preference": preference, "warning": warning}

async def run_daily_cleanup_loop():
    while True:
        print("Running scheduled database cleanup via lifespan worker...")
        try:
            conn = psycopg2.connect(DB_PATH)
            cursor = conn.cursor()

            current_date = utilities.get_current_ist_datetime().strftime("%Y-%m-%d")
            cursor.execute("DELETE FROM special_config WHERE to_date < %s", (current_date,))
            conn.commit()
            print("Cleanup for special_config old data done successfully!")
        except Exception as e:
            print(f"Cleanup couldn't be completed. Error: {str(e)}")
        finally:
            if 'cursor' in locals(): cursor.close()
            if 'conn' in locals(): conn.close()
        
        # Sleep for 24 hours before next cleanup
        await asyncio.sleep(60 * 60 * 24)

@asynccontextmanager
async def lifespan_tasks(app: FastAPI):
    print("Server booting up... Launching Background Tasks...")
    cleanup_task = asyncio.create_task(run_daily_cleanup_loop())
    yield

    print("Server shutting down... Cancelling worker tasks...")
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError as e:
        print("Background Task Cancelled:", str(e))

hasher = PasswordHasher()
authenticator = Authenticator(DB_PATH, SECRET_KEY)
app = FastAPI(title="Hostel Canteen Central Node",
              lifespan=lifespan_tasks,
              dependencies=[Depends(authenticator.verify_frontend_app_authenticity)])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from any client machine
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ALLOWED_CONFIG_KEYS = {"breakfast_time_slot", "lunch_time_slot", "dinner_time_slot", "only_veg_days"} # more to be added later
utilities = UtilityFunctions()
utilities.initialize_database()

@app.get("/")
def home_root():
    return {"message": "The Canteen Backend is fully live and online!"}

@app.post("/api/configure-settings")
def configure_settings(key: str, value: str) -> Dict[str, str]:
    if key not in ALLOWED_CONFIG_KEYS:
        raise HTTPException(
            status_code=400,
            detail=f"Modification of the configuration key '{key}' is restricted or invalid."
        )
        
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """
                INSERT INTO settings (key, value)
                VALUES (%s, %s)
                ON CONFLICT (key)
                DO UPDATE SET value = EXCLUDED.value
            """, (key, value)
        )
        utilities.invalidate_client_cache(cursor)
        conn.commit()
        return {
            "status": "success",
            "message": f"Configuration setting '{key}' successfully updated to '{value}'."
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        utilities.close_connection_raise_error(conn, cursor)

@app.get("/api/get-existing-token-stats")
def get_existing_token_stats() -> Dict[str, int]:
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
                SELECT 
                COUNT(*) AS total, 
                COUNT(*) FILTER (WHERE card_status = 'AVAILABLE') AS available,
                COUNT(*) FILTER (WHERE card_status = 'ASSIGNED') AS assigned,
                COALESCE(MAX(token_number), 0) AS max_number
                FROM physical_qr_tokens
            """
        )

        total, available, assigned, max_number = cursor.fetchone()
        return {
            "total": total, "available": available,
            "assigned": assigned, "max_number": max_number
        }
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        utilities.close_connection_raise_error(conn, cursor)

@app.get("/api/get-available-tokens")
def get_available_tokens() -> Dict[str, List[int]]:
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT token_number FROM physical_qr_tokens WHERE card_status = 'AVAILABLE'")
        token_numbers = [row[0] for row in cursor.fetchall()]
        return {"token_numbers": token_numbers}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        utilities.close_connection_raise_error(conn, cursor)

@app.get("/api/get-trainee-list")
def get_trainee_list() -> Dict[str, List[Any]]:
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT p.token_number, t.trainee_name, t.trainee_desg
            FROM physical_qr_tokens AS p JOIN trainee_assignments t
            ON p.token_id = t.token_id
            WHERE t.is_active = 1
            """
        )
        trainees = cursor.fetchall()
        return {"trainees": trainees}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        utilities.close_connection_raise_error(conn, cursor)

@app.post("/api/generate-new-token")
def generate_new_token(total_tokens) -> Dict[str, Union[str, Any]]:
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT COALESCE(MAX(token_number), 0) + %s FROM physical_qr_tokens", (total_tokens,))
        search_limit = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT s.num FROM generate_series(1, %s) AS s(num)
            LEFT JOIN physical_qr_tokens p ON s.num = p.token_number
            WHERE p.token_number IS NULL
            LIMIT %s
            """, (search_limit, total_tokens)
        )

        new_token_numbers = [row[0] for row in cursor.fetchall()]
        bulk_data = []
        for token_number in new_token_numbers:
            token_hash = hasher.create_hash(str(token_number))
            token_id = f"{token_number}.{token_hash}"
            bulk_data.append((token_number, token_id))
        response_data = [{"token_number": data[0], "token_id": data[1]} for data in bulk_data]

        query = "INSERT INTO physical_qr_tokens (token_number, token_id) VALUES %s"
        execute_values(cursor, query, bulk_data)
        conn.commit()
        return {"status": "success", "inserted_count": len(bulk_data), "tokens": response_data}

    # Check - Did the database refuse to insert the entry?
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        utilities.close_connection_raise_error(conn, cursor)

@app.post("/api/assign-token")
def assign_token_to_trainee(
    token_number: int,
    trainee_name: str,
    trainee_desg: str,
    course_start: str,
    course_end: str,
    meal_preference: str,
) -> Dict[str, Union[str, int]]:
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT token_id, card_status FROM physical_qr_tokens WHERE token_number = %s", (token_number,))
        res = cursor.fetchone()

        # Check - Is the QR token a valid one (available physically)?
        if not res:
            utilities.close_connection_raise_error(conn, cursor, 400, "Physical QR Token not found in stock inventory!")
        else:
            token_id, card_status = res

        # Check - Is the QR already assigned to another trainee?
        if card_status != "AVAILABLE":
            utilities.close_connection_raise_error(conn, cursor, 400, "The requested Physical QR is already assigned to a trainee!")

        cursor.execute("UPDATE physical_qr_tokens SET card_status = 'ASSIGNED' WHERE token_number = %s", (token_number,))
        cursor.execute(
            '''
                INSERT INTO trainee_assignments (token_id, trainee_name, trainee_desg,
                course_start_date, course_end_date, meal_preference)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (token_id, trainee_name, trainee_desg, course_start, course_end, meal_preference)
        )
        utilities.invalidate_client_cache(cursor)
        conn.commit()
        return {"status": "success", "token_number": token_number, "trainee_name": trainee_name}
    
    # Check - Did the database refuse to insert the entry?
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        utilities.close_connection_raise_error(conn, cursor)

@app.post("/api/verify-token")
def verify_scanned_token(token_id: str) -> Dict[str, Union[str, int]]:
    parts = token_id.split('.')
    if (len(parts)!=2):
        raise HTTPException(status_code=404, detail="Invalid QR Code Scanned! (Invalid Format)")
    token_number, token_hash_code = parts

    if not hasher.check_password(token_number, token_hash_code):
        raise HTTPException(status_code=404, detail="Invalid QR Code scanned! (Invalid Hash)")

    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT 1 FROM physical_qr_tokens WHERE token_id = %s", (token_id,))
        res = cursor.fetchone()

        # Check - Is the QR scanned a valid token?
        if not res:
            utilities.close_connection_raise_error(conn, cursor, 404, "Invalid QR Code scanned! (Invalid Token Number)")
        
        return utilities.verify_token_and_supply_data(conn, cursor, token_id=token_id, token_number=token_number)
        
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        utilities.close_connection_raise_error()

@app.post("/api/verify-token-manual")
def verify_typed_token(token_number: int) -> Dict[str, Union[str, int]]:
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT token_id FROM physical_qr_tokens WHERE token_number = %s", (token_number,))
        res = cursor.fetchone()

        # Check - Is the QR scanned a valid token?
        if not res:
            utilities.close_connection_raise_error(conn, cursor, 404, "Invalid Token Number (Not Registered)")
        else:
            token_id = res[0]
        
        return utilities.verify_token_and_supply_data(conn, cursor, token_id=token_id, token_number=token_number)

    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        utilities.close_connection_raise_error()

@app.post("/api/apply-special-config")
def set_special_config_for_trainee(
    token_number_arr: list[int],
    date_interval_arr: list[tuple[str, str]],
    breakfast_time_slot: Union[str, None] = None,
    lunch_time_slot: Union[str, None] = None,
    dinner_time_slot: Union[str, None] = None,
    is_suspended: Union[bool, None] = None
) -> Dict[str, str]:
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        for token_number in token_number_arr:
            # List of all dates that are queried to be configured are stored (for each token_number)
            all_incoming_dates: list[datetime] = []

            # For each date interval, we extract each date from it and store it in all_incoming_dates (as date)
            for date_interval in date_interval_arr:
                start_date, end_date = list(map(lambda x: datetime.strptime(x.strip(), "%Y-%m-%d").date(), date_interval))
                curr = start_date
                while curr <= end_date:
                    all_incoming_dates.append(curr)
                    curr += timedelta(days=1)
            
            if not all_incoming_dates:
                continue

            # We calculate the lower bound and upper bound of all the queried dates
            min_bound = min(all_incoming_dates).strftime("%Y-%m-%d")
            max_bound = max(all_incoming_dates).strftime("%Y-%m-%d")

            # We collect those rows where the existing date intervals overlap with queried dates
            cursor.execute('''
                        SELECT exception_id, from_date, to_date, breakfast_time_slot,
                        lunch_time_slot, dinner_time_slot, is_suspended
                        FROM special_config
                        WHERE token_number = %s AND NOT (to_date < %s OR from_date > %s)
                        ''', (token_number, min_bound, max_bound)
                        )
            
            # Overlapping rows array (list of tuples)
            overlapping_rows = cursor.fetchall()

            # Dictionary to store date (key) and Configuration JSON (value)
            calendar: Dict[DATE, Dict[str, Any]] = {}

            # List of row_ids (exception_id) to be deleted from the database (and later replaced)
            row_ids_to_delete = []

            # Iterate over all rows in the overlapping_rows
            for row in overlapping_rows:
                # Delete every row from the overlaping_rows list
                row_id, from_str, to_str, breakfast, lunch, dinner, susp = row
                row_ids_to_delete.append(row_id)

                # For every interval in each row, we extract each date and map it to the configuration JSON to store in calendar
                from_date, to_date = list(map(lambda x: datetime.strptime(x.strip(), "%Y-%m-%d").date(), (from_str, to_str)))
                curr = from_date
                while curr <= to_date:
                    calendar[curr] = {
                        "breakfast": breakfast, "lunch": lunch, "dinner": dinner, "is_suspended": susp
                    }
                    curr += timedelta(days=1)
            
            # Iterate over all the queried dates all_incoming_dates
            for date in all_incoming_dates:

                # If a date was present in the database and also in the query then edit the config (where value not NULL)
                if date in calendar:
                    calendar[date]["breakfast"] = breakfast_time_slot or calendar[date]["breakfast"]
                    calendar[date]["lunch"] = lunch_time_slot or calendar[date]["lunch"]
                    calendar[date]["dinner"] = dinner_time_slot or calendar[date]["dinner"]
                    calendar[date]["is_suspended"] = is_suspended if is_suspended is not None else calendar[date]["is_suspended"]

                # If a date is not present in the database but is in the query then simply create the config using parameters
                else:
                    calendar[date] = {
                        "breakfast": breakfast_time_slot,
                        "lunch": lunch_time_slot,
                        "dinner": dinner_time_slot,
                        "is_suspended": is_suspended
                    }
            
            # Sort the dates (alrady in the database overlapping region)
            sorted_dates = sorted(calendar.keys())

            # List to carry new tuples to be inserted in the database
            new_intervals: list[tuple] = []

            # If calender is not empty (i.e., some overlapping is there)
            if sorted_dates:
                start_date = sorted_dates[0]
                prev_date = sorted_dates[0]
                current_config = calendar[start_date]

                # Traverse the overlapping dates in sorted order to create intervals
                for current_date in sorted_dates[1:]:
                    # To merge dates in same row, dates must be -
                    # 1. Consecutive (curr = prev + 1)
                    # 2. The config data must be same for both (config[curr] = config[prev])
                    if (current_date == prev_date + timedelta(days=1)) and (calendar[current_date] == current_config):
                        prev_date = current_date

                    # If curr can't be merged in the same row, save the last merged interval and start a new one
                    else:
                        new_intervals.append((
                            token_number, start_date.strftime("%Y-%m-%d"), prev_date.strftime("%Y-%m-%d"),
                            current_config["breakfast"], current_config["lunch"],
                            current_config["dinner"], current_config["is_suspended"]
                        ))

                        start_date = current_date
                        prev_date = current_date
                        current_config = calendar[start_date]
                    
                # Append the last interval block (that was left)
                new_intervals.append((
                    token_number, start_date.strftime("%Y-%m-%d"), prev_date.strftime("%Y-%m-%d"),
                    current_config["breakfast"], current_config["lunch"],
                    current_config["dinner"], current_config["is_suspended"]
                ))

            # Delete the previous interval blocks
            if row_ids_to_delete:
                cursor.execute("DELETE FROM special_config WHERE exception_id = ANY(%s)", (row_ids_to_delete,))
            
            # Insert all the rows in one query using execute_values()
            if new_intervals:
                query = '''
                        INSERT INTO special_config (token_number, from_date, to_date,
                        breakfast_time_slot, lunch_time_slot, dinner_time_slot, is_suspended)
                        VALUES %s
                        '''
                execute_values(cursor, query, new_intervals)

        utilities.invalidate_client_cache(cursor)
        conn.commit()
        return {"status": "success", "message": "New custom configurations applied!"}
    
    except Exception as e:
        conn.rollback()
        utilities.close_connection_raise_error(conn, cursor, 500, str(e))
    finally:
        utilities.close_connection_raise_error(conn, cursor)

@app.post("/api/change-course-interval")
def change_course_interval(
    token_number_arr: List[int] = Query(...),
    new_end_date: str = Query(...)
) -> Dict[str, str]:
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT token_id FROM physical_qr_tokens WHERE token_number = ANY(%s)", (token_number_arr,))
        res = cursor.fetchall()
        if not res:
            utilities.close_connection_raise_error(conn, cursor, 404, "None of the token numbers is valid")
        
        token_id_arr = [row[0] for row in res]
    
        cursor.execute('''
                    UPDATE trainee_assignments SET
                    course_end_date = COALESCE(%s, course_end_date)
                    WHERE token_id = ANY(%s) AND is_active = 1
                    ''', (new_end_date, token_id_arr)
                    )
        conn.commit()
        return {"status": "success", "message": f"Course Duration updated successfully for {len(token_id_arr)} trainees"}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        utilities.close_connection_raise_error(conn, cursor)

@app.post("/api/destroy-token")
def destroy_wasted_token(
    token_number: int,
    replaced_token_number: Union[int, None] = None
) -> Dict[str, str]:
    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT token_id, card_status FROM physical_qr_tokens WHERE token_number = %s", (token_number,))
        res = cursor.fetchone()

        if not res:
            utilities.close_connection_raise_error(conn, cursor, 404, "Invalid Token Number!")
        
        token_id, card_status = res
        if card_status == "ASSIGNED":
            if replaced_token_number is None:
                utilities.close_connection_raise_error(
                    conn, cursor, 422,
                    "Token is assigned to a trainee, and needs another token to substitute!"
                )
            cursor.execute(
                """
                SELECT token_id FROM physical_qr_tokens
                WHERE token_number = %s AND card_status = 'AVAILABLE'
                """, (replaced_token_number,)
            )
            res = cursor.fetchone()

            if not res:
                utilities.close_connection_raise_error(
                    conn, cursor, 404,
                    "The Substitute Token is not available for assignment!"
                )
            
            replaced_token_id = res[0]
            cursor.execute("UPDATE trainee_assignments SET token_id = %s WHERE token_id = %s", (replaced_token_id, token_id))
            cursor.execute("UPDATE physical_qr_tokens SET card_status = 'ASSIGNED' WHERE token_id = %s", (replaced_token_id,))
            cursor.execute(
                "UPDATE special_config SET token_number = %s WHERE token_number = %s",
                (replaced_token_number, token_number)
            )
        
        cursor.execute("DELETE FROM physical_qr_tokens WHERE token_number = %s", (token_number,))
        conn.commit()
        return {"status": "success", "message": f"Successfully removed Token No. ({token_number}) from database!"}
    
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        utilities.close_connection_raise_error(conn, cursor)

@app.post("/api/sync-nudge")
def send_updates_if_any(last_sync_str: str) -> Dict[str, Any]:
    last_sync_time = datetime.fromisoformat(last_sync_str)
    current_time = utilities.get_current_ist_datetime()
    current_time_str = current_time.isoformat()

    conn = psycopg2.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT value FROM settings WHERE key = 'last_updated'")
        res = cursor.fetchone()

        if not res:
            cursor.execute(
                '''
                    INSERT INTO settings (key, value)
                    VALUES ('last_updated', %s)
                ''', (current_time_str,)
            )
            last_updated_str = current_time_str
        else:
            last_updated_str = res[0]
        
        last_updated_time = datetime.fromisoformat(last_updated_str)
        cursor.execute(
            '''
                INSERT INTO settings (key, value)
                VALUES ('last_polled', %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            ''', (current_time_str,)
        )
        conn.commit()

        # Trainee or tokens updated after last sync
        if last_updated_time > last_sync_time:
            cursor.execute("SELECT key, value FROM settings WHERE key LIKE '%_time_slot'")
            settings = {key: value for key, value in cursor.fetchall()}
            
            cursor.execute(
                '''SELECT 
                    p.token_number,
                    t.token_id,
                    t.trainee_name,
                    t.trainee_desg,
                    t.course_start_date,
                    t.course_end_date,
                    t.meal_preference
                FROM trainee_assignments AS t
                INNER JOIN physical_qr_tokens AS p
                ON t.token_id = p.token_id WHERE t.is_active = 1'''
            )
            assignments = [
                {
                    "token_number": token_number,
                    "token_id": token_id,
                    "trainee_name": name,
                    "trainee_desg": desg,
                    "course_start_date": start,
                    "course_end_date": end,
                    "meal_preference": preference
                }
                for token_number, token_id, name, desg, start, end, preference in cursor.fetchall()
            ]

            cursor.execute(
                '''
                    SELECT token_number, from_date, to_date, breakfast_time_slot,
                    lunch_time_slot, dinner_time_slot, is_suspended
                    FROM special_config WHERE to_date >= %s
                ''', (current_time.strftime("%Y-%m-%d"),))
            exceptions = [
                {
                    "token_number": token,
                    "from_date": from_d,
                    "to_date": to_d,
                    "breakfast_time_slot": breakfast,
                    "lunch_time_slot": lunch,
                    "dinner_time_slot": dinner,
                    "is_suspended": susp
                }
                for token, from_d, to_d, breakfast, lunch, dinner, susp in cursor.fetchall()
            ]

            return {
                "status": "synced_now",
                "server_sync_time": current_time_str,
                "assignments": assignments,
                "settings": settings,
                "exceptions": exceptions
            }
        
        return {"status": "up_to_date", "server_sync_time": current_time_str}
            
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        utilities.close_connection_raise_error(conn, cursor)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("LISTEN_PORT")))