from typing import Dict, Union
import psycopg2
from fastapi import HTTPException, FastAPI
from dotenv import load_dotenv
from contextlib import contextmanager, asynccontextmanager
import os
from datetime import datetime, timezone, timedelta
import asyncio

load_dotenv()
DB_PATH = os.getenv("DATABASE_URI")
SECRET_KEY = os.getenv("MUTUAL_SECRET_KEY")

class UtilityFunctions:
    @staticmethod
    @contextmanager
    def get_connection(db_path: str = DB_PATH):
        conn = None
        cursor = None
        try:
            conn = psycopg2.connect(db_path)
            cursor = conn.cursor()
            yield cursor

            if conn and not conn.closed:
                conn.commit()

        except HTTPException:
            if conn and not conn.closed:
                conn.rollback()
            raise
        except Exception as e:
            if conn and not conn.closed:
                conn.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            if cursor and not cursor.closed:
                cursor.close()
            if conn and not conn.closed:
                conn.close()

    @staticmethod
    def initialize_database():
        with UtilityFunctions.get_connection() as cursor:
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
                                meal_type TEXT,
                                CONSTRAINT unique_scan UNIQUE (assignment_id, scan_date, scan_time),
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

    @staticmethod
    def is_time_in_slot(check_time: str, time_slot: str) -> bool:
        start_time, end_time = tuple(map(lambda x: datetime.strptime(x.strip(), "%H:%M:%S").time(), time_slot.split('-')))
        measurable_check_time = datetime.strptime(check_time.strip(), "%H:%M:%S").time()

        if start_time <= end_time:
            return (start_time <= measurable_check_time <= end_time)
        else:
            return (start_time <= measurable_check_time or measurable_check_time <= end_time)

    @staticmethod
    def get_current_ist_datetime() -> datetime:
        aware_current_time_utc = datetime.now(timezone.utc)
        aware_current_time_ist = aware_current_time_utc + timedelta(hours=5, minutes=30)
        current_time_ist = aware_current_time_ist.replace(tzinfo=None)
        return current_time_ist
    
    @staticmethod
    def get_date_string(datetime_obj: datetime) -> str:
        return datetime_obj.strftime("%Y-%m-%d")

    @staticmethod
    def get_time_string(datetime_obj: datetime) -> str:
        return datetime_obj.strftime("%H:%M:%S")

    @staticmethod
    def get_date_obj(datetime_str: str) -> datetime:
        return datetime.strptime(datetime_str.strip(), "%Y-%m-%d").date()

    @staticmethod
    def get_time_obj(datetime_str: str) -> datetime:
        return datetime.strptime(datetime_str.strip(), "%H:%M:%S").time()
    
    @staticmethod
    def invalidate_client_cache(cursor: psycopg2.extensions.cursor) -> None:
        cursor.execute(
            """
                INSERT INTO settings (key, value)
                VALUES ('last_updated', %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            (UtilityFunctions.get_current_ist_datetime().isoformat(),)
        )
    
    @staticmethod
    def verify_token_and_supply_data(
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

        # Check - Is the QR token assigned to a trainee?
        if not trainee_data:
            raise HTTPException(status_code=404, detail="There is no trainee assigned to this Physical QR Token")
        else:
            assignment_id, name, desg, start_date, end_date, preference = trainee_data
        
        current_datetime = UtilityFunctions.get_current_ist_datetime()
        current_date = UtilityFunctions.get_date_string(current_datetime)
        current_time = UtilityFunctions.get_time_string(current_datetime)

        # Check - Did the QR token expire for that trainee?
        start_date_obj = UtilityFunctions.get_date_obj(start_date)
        end_date_obj = UtilityFunctions.get_date_obj(end_date)

        if (start_date_obj > current_datetime.date()):
            raise HTTPException(status_code=403, detail="Physical QR Token not valid yet (Course not started)!")
        if (end_date_obj < current_datetime.date()):
            raise HTTPException(status_code=403, detail="Physical QR Token expired for the trainee!")

        cursor.execute("SELECT key, value FROM settings WHERE key LIKE '%_time_slot' OR key = 'only_veg_days'")
        settings: Dict[str, str] = {key:value for (key, value) in cursor.fetchall()}

        time_slot_keys = ("breakfast_time_slot", "lunch_time_slot", "dinner_time_slot")

        # Check - Have the Meal Slot Timing Settings been initialized?
        if not all([slot in settings for slot in time_slot_keys]):
            raise HTTPException(status_code=422, detail="Meal Time Slot configuration data not found!")

        active_breakfast_slot = settings.get(time_slot_keys[0])
        active_lunch_slot = settings.get(time_slot_keys[1])
        active_dinner_slot = settings.get(time_slot_keys[2])
        only_veg_days = settings.get("only_veg_days")

        if only_veg_days and only_veg_days.strip():
            only_veg_days_arr = [day.strip().title() for day in only_veg_days.split(',') if day.strip()]
            if current_datetime.strftime("%a") in only_veg_days_arr:
                preference = "VEG (same for all today)"

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
                raise HTTPException(
                    status_code=403,
                    detail=f"Trainee (Token ID - {token_number}) is suspended from meals today!"
                )

            active_breakfast_slot = custom_breakfast_slot or active_breakfast_slot
            active_lunch_slot = custom_lunch_slot or active_lunch_slot
            active_dinner_slot = custom_dinner_slot or active_dinner_slot
        
        time_slot_names = ("BREAKFAST", "LUNCH", "DINNER")
        active_time_slots = (active_breakfast_slot, active_lunch_slot, active_dinner_slot)
        
        matched_slot_name = None
        # matched_slot_value = None

        for slot_type, slot in zip(time_slot_names, active_time_slots):
            if UtilityFunctions.is_time_in_slot(current_time, slot):
                matched_slot_name = slot_type
                # matched_slot_value = slot
                break
        
        if not matched_slot_name:
            # Check - Is it the correct time to scan the QR? (No meals right now)
            raise HTTPException(status_code=403, detail="Not a valid meal slot! Try again later!")

        cursor.execute(
            "SELECT meal_type FROM qr_scans WHERE assignment_id = %s AND scan_date = %s",
            (assignment_id, current_date)
        )
        meals_taken_today = [res[0] for res in cursor.fetchall()]

        if matched_slot_name in meals_taken_today:
            raise HTTPException(
                status_code=403,
                detail=f"Trainee (Token ID - {token_number}) has already taken the meal for {matched_slot_name}!"
            )
        
        # cursor.execute(
        #     "SELECT scan_time FROM qr_scans WHERE assignment_id = %s AND scan_date = %s",
        #     (assignment_id, current_date)
        # )
        # scan_times_today = [res[0] for res in cursor.fetchall()]

        # for scan_time in scan_times_today:
        #     # Check - Has the trainee already taken the meal receipt for that slot that day?
        #     if UtilityFunctions.is_time_in_slot(scan_time, matched_slot_value):
        #         raise HTTPException(status_code=403, detail=f"The trainee has already taken the meal for {matched_slot_name.upper()}!")

        cursor.execute(
            '''INSERT INTO qr_scans (assignment_id, scan_date, scan_time, meal_type)
            VALUES (%s, %s, %s, %s)''', (assignment_id, current_date, current_time, matched_slot_name)
        )

        return {"status": "success", "token_number": token_number, "trainee_name": name,
                "trainee_desg": desg, "meal_preference": preference, "meal_type": matched_slot_name}
    
    @staticmethod
    async def run_daily_cleanup_loop():
        while True:
            print("Running scheduled database cleanup via lifespan worker...")

            try:
                with UtilityFunctions.get_connection() as cursor:
                    current_date = UtilityFunctions.get_date_string(UtilityFunctions.get_current_ist_datetime())
                    cursor.execute("DELETE FROM special_config WHERE to_date < %s", (current_date,))
                print("Cleanup for special_config old data done successfully!")
            except Exception as e:
                print(f"Error occurred during background database cleanup: {e}")
            
            # Sleep for 24 hours before next cleanup
            await asyncio.sleep(60 * 60 * 24)

    @staticmethod
    @asynccontextmanager
    async def lifespan_tasks(app: FastAPI):
        print("Server booting up... Launching Background Tasks...")
        UtilityFunctions.initialize_database()

        print("Launching background tasks...")
        cleanup_task = asyncio.create_task(UtilityFunctions.run_daily_cleanup_loop())
        yield

        print("Server shutting down... Cancelling worker tasks...")
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError as e:
            print("Background Task Cancelled:", str(e))