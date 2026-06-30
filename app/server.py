from typing import Dict, Union, Any, List
from psycopg2.extras import execute_values
from datetime import datetime, timedelta, date as DATE
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
import os
from password_hasher import PasswordHasher
from security_gateway import Authenticator
from utils import UtilityFunctions, DB_PATH, SECRET_KEY
import models

hasher = PasswordHasher()
authenticator = Authenticator(DB_PATH, SECRET_KEY)
app = FastAPI(title="Hostel Canteen Central Node",
              lifespan=UtilityFunctions.lifespan_tasks,
              dependencies=[Depends(authenticator.verify_frontend_app_authenticity)])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from any client machine
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ALLOWED_CONFIG_KEYS = {"breakfast_time_slot", "lunch_time_slot", "dinner_time_slot", "only_veg_days"} # more to be added later
UtilityFunctions.initialize_database()

@app.get("/")
def home_root():
    return {"message": "The Canteen Backend is fully live and online!"}

@app.post("/api/configure-settings")
def configure_settings(payload: models.SettingsPayload) -> Dict[str, str]:
    for item in payload.settings:
        if item.key not in ALLOWED_CONFIG_KEYS:
            raise HTTPException(
                status_code=400,
                detail=f"Modification of the configuration key '{item.key}' is restricted or invalid."
            )

    with UtilityFunctions.get_connection() as cursor:
        query = """
            INSERT INTO settings (key, value)
            VALUES %s
            ON CONFLICT (key)
            DO UPDATE SET value = EXCLUDED.value
        """
        settings_tuple = [(item.key, item.value) for item in payload.settings]
        execute_values(cursor, query, settings_tuple)
        UtilityFunctions.invalidate_client_cache(cursor)

        return {"status": "success", "message": f"Settings updated successfully!"}

@app.post("/api/add-user")
def add_user(payload: models.AddUserPayload) -> Dict[str, str]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT 1 FROM user_info WHERE role = %s", (payload.role,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail=f"{payload.role.title()} already exists for the app!")

        cursor.execute(
            "INSERT INTO user_info (role, email, username, password_hash) VALUES (%s, %s, %s, %s)",
            (payload.role, payload.email, payload.username, payload.password_hash)
        )

        return {"status": "success", "role": payload.role, "email": payload.email}

@app.get("/api/verify-user")
def verify_user(payload: models.VerifyUserPayload) -> Dict[str, str]:
    with UtilityFunctions.get_connection() as cursor:
        if payload.email is None:
            cursor.execute(
                "SELECT email, password_hash FROM user_info WHERE username = %s AND role = %s",
                (payload.username, payload.role)
            )
        else:
            cursor.execute(
                "SELECT email, password_hash FROM user_info WHERE email = %s AND role = %s",
                (payload.email, payload.role)
            )
        
        res = cursor.fetchone()
        if not res:
            raise HTTPException(status_code=401, detail="Email/Username not found!")
        
        email, password_hash = res
        if not hasher.check_password(payload.password, password_hash):
            raise HTTPException(status_code=401, detail="Invalid Password!")

        return {"status": "valid", "role": payload.role, "email": email}

@app.get("/api/verify-user-email")
def verify_user_email(role: str, email: str):
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT 1 FROM user_info WHERE email = %s AND role = %s", (email, role))
        if cursor.fetchone():
            return {"status": "valid"}
        else:
            raise HTTPException(status_code=404, detail="Wrong Email ID Provided. Couldn't Verify!")

@app.post("/api/change-user-password")
def change_user_password(payload: models.ChangePasswordPayload):
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute(
            "UPDATE user_info SET password_hash = %s WHERE role = %s AND email = %s",
            (payload.password_hash, payload.role, payload.email)
        )
        return {"status": "success"}
        

@app.get("/api/get-existing-token-stats")
def get_existing_token_stats() -> Dict[str, int]:
    with UtilityFunctions.get_connection() as cursor:
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
    
@app.get("/api/get-tokens-by-status")
def get_tokens_by_status() -> Dict[str, List[int]]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT token_number FROM physical_qr_tokens WHERE card_status = 'AVAILABLE'")
        available = [row[0] for row in cursor.fetchall()]
        cursor.execute("SELECT token_number FROM physical_qr_tokens WHERE card_status = 'ASSIGNED'")
        assigned = [row[0] for row in cursor.fetchall()]

        return {"tokens_available": available, "tokens_assigned": assigned}

@app.get("/api/get-available-tokens-number-and-id")
def get_available_tokens_number_and_id() -> Dict[str, List[Any]]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT token_number, token_id FROM physical_qr_tokens WHERE card_status = 'AVAILABLE'")
        res = cursor.fetchall()
        tokens = [{"token_number": row[0], "token_id": row[1]} for row in res]
        return {"tokens": tokens}
    
@app.get("/api/get-trainee-list")
def get_trainee_list() -> Dict[str, List[Any]]:
    with UtilityFunctions.get_connection() as cursor:
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

@app.get("/api/get-settings")
def get_settings() -> Dict[str, Any]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT key, value FROM settings")
        settings = {key:value for (key, value) in cursor.fetchall()}
        return settings

@app.get("/api/get-total-meal-data")
def get_total_meal_data() -> Dict[str, int]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT value FROM settings WHERE key = 'only_veg_days'")
        res = cursor.fetchone()
        only_veg_days = res[0] if res else ""
        veg_day_list = [day.strip().title() for day in only_veg_days.split(',') if day.strip()]

        target_datetime = UtilityFunctions.get_current_ist_datetime()
        target_day = target_datetime.strftime("%a")
        target_date = UtilityFunctions.get_date_string(target_datetime)

        cursor.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE ta.meal_preference = 'VEG' AND COALESCE(sc.is_suspended, False) = False) AS veg,
                COUNT(*) FILTER (WHERE ta.meal_preference = 'NON-VEG' AND COALESCE(sc.is_suspended, False) = False) AS non_veg
            FROM trainee_assignments AS ta
            LEFT JOIN special_config AS sc ON 
                sc.token_number = (SELECT token_number FROM physical_qr_tokens WHERE token_id = ta.token_id)
                AND %s BETWEEN sc.from_date AND sc.to_date
            WHERE
                %s >= ta.course_start_date 
                AND %s <= ta.course_end_date
                AND ta.is_active = 1
            """, (target_date, target_date, target_date)
        )
        res = cursor.fetchone()
        veg_count = res[0] if (res and res[0] is not None) else 0
        non_veg_count = res[1] if (res and res[1] is not None) else 0

        if target_day in veg_day_list:
            veg_count += non_veg_count
            non_veg_count = 0

        return {"veg": veg_count, "non-veg": non_veg_count}

@app.get("/api/get-scanned-meal-data")
def get_scanned_meal_data(target_date: str) -> Dict[str, Dict[str, int]]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT value FROM settings WHERE key = 'only_veg_days'")
        res = cursor.fetchone()
        only_veg_days = res[0] if res else ""
        veg_day_list = [day.strip().title() for day in only_veg_days.split(',') if day.strip()]
        target_day = UtilityFunctions.get_date_obj(target_date).strftime("%a")

        cursor.execute(
            """
            SELECT
                q.meal_type,
                COUNT(*) FILTER (WHERE t.meal_preference = 'VEG') AS veg_count,
                COUNT(*) FILTER (WHERE t.meal_preference = 'NON-VEG') AS non_veg_count
            FROM qr_scans AS q INNER JOIN trainee_assignments AS t
            ON q.assignment_id = t.assignment_id
            WHERE q.scan_date = %s
            GROUP BY q.meal_type
            ORDER BY q.meal_type;
            """, (target_date,)
        )
        res = cursor.fetchall()

        if not res:
            return {}

        meal_stats = {
            row[0]: {
                "veg": row[1] if (row and row[1] is not None) else 0,
                "non-veg": row[2] if (row and row[2] is not None) else 0,
            } 
            for row in res
        }

        if target_day in veg_day_list:
            for meal_type in meal_stats:
                veg = meal_stats[meal_type]["veg"]
                non_veg = meal_stats[meal_type]["non-veg"]

                meal_stats[meal_type]["veg"] = veg + non_veg
                meal_stats[meal_type]["non-veg"] = 0

        return meal_stats

@app.post("/api/generate-new-token")
def generate_new_token(payload: models.GenerateTokensPayload) -> Dict[str, Union[str, Any]]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT COALESCE(MAX(token_number), 0) + %s FROM physical_qr_tokens", (payload.total_tokens,))
        search_limit = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT s.num FROM generate_series(1, %s) AS s(num)
            LEFT JOIN physical_qr_tokens p ON s.num = p.token_number
            WHERE p.token_number IS NULL
            LIMIT %s
            """, (search_limit, payload.total_tokens)
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
        return {"status": "success", "inserted_count": len(bulk_data), "tokens": response_data}

@app.post("/api/assign-token")
def assign_token_to_trainee(payload: models.AssignTokenPayload) -> Dict[str, Union[str, int]]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute(
            "SELECT token_id, card_status FROM physical_qr_tokens WHERE token_number = %s FOR UPDATE",
            (payload.token_number,))
        res = cursor.fetchone()

        # Check - Is the QR token a valid one (available physically)?
        if not res:
            raise HTTPException(status_code=400, detail="Physical QR Token not found in stock inventory!")
        
        token_id, card_status = res

        # Check - Is the QR already assigned to another trainee?
        if card_status != "AVAILABLE":
            raise HTTPException(status_code=400, detail="The requested Physical QR is already assigned to a trainee!")

        cursor.execute("UPDATE physical_qr_tokens SET card_status = 'ASSIGNED' WHERE token_number = %s", (payload.token_number,))
        cursor.execute(
            '''
                INSERT INTO trainee_assignments (token_id, trainee_name, trainee_desg,
                course_start_date, course_end_date, meal_preference)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (token_id, payload.trainee.name, payload.trainee.designation,
                  payload.trainee.course_start, payload.trainee.course_end, payload.trainee.meal_preference)
        )
        UtilityFunctions.invalidate_client_cache(cursor)
        return {"status": "success", "token_number": payload.token_number, "trainee_name": payload.trainee.name}

@app.post("/api/verify-token")
def verify_scanned_token(payload: models.VerifyScannedTokenPayload) -> Dict[str, Union[str, int]]:
    parts = payload.token_id.split('.')
    if (len(parts)!=2):
        raise HTTPException(status_code=400, detail="Invalid QR Code Scanned! (Invalid Format)")
    token_number, token_hash_code = parts

    try:
        token_number = int(token_number)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Token Number (within QR Code)")

    if not hasher.check_password(str(token_number), token_hash_code):
        raise HTTPException(status_code=400, detail="Invalid QR Code scanned! (Invalid Hash)")

    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT 1 FROM physical_qr_tokens WHERE token_id = %s", (payload.token_id,))
        res = cursor.fetchone()

        # Check - Is the QR scanned a valid token?
        if not res:
            raise HTTPException(status_code=404, detail="Invalid QR Code scanned! (Invalid Token Number)")
        
        return UtilityFunctions.verify_token_and_supply_data(cursor, token_id=payload.token_id, token_number=token_number)

@app.post("/api/verify-token-manual")
def verify_typed_token(payload: models.VerifyTypedTokenPayload) -> Dict[str, Union[str, int]]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT token_id FROM physical_qr_tokens WHERE token_number = %s", (payload.token_number,))
        res = cursor.fetchone()

        # Check - Is the QR scanned a valid token?
        if not res:
            raise HTTPException(status_code=404, detail="Invalid Token Number (Not Registered)")
        
        token_id = res[0]
        
        return UtilityFunctions.verify_token_and_supply_data(cursor, token_id=token_id, token_number=payload.token_number)

@app.post("/api/apply-special-config")
def set_special_config_for_trainee(payload: models.SpecialConfigPayload) -> Dict[str, str]:
    # List of all dates that are queried to be configured are stored (for each token_number)
    all_incoming_dates: List[datetime] = []
    # For each date interval, we extract each date from it and store it in all_incoming_dates (as date)
    for date_interval in payload.date_interval_arr:
        start_date, end_date = list(map(
            UtilityFunctions.get_date_obj,
            date_interval.split('T')
        ))
        curr = start_date
        while curr <= end_date:
            all_incoming_dates.append(curr)
            curr += timedelta(days=1)
    
    if not all_incoming_dates:
        return {"status": "success", "message": "No valid dates provided."}

    # We calculate the lower bound and upper bound of all the queried dates
    min_bound = UtilityFunctions.get_date_string(min(all_incoming_dates))
    max_bound = UtilityFunctions.get_date_string(max(all_incoming_dates))

    with UtilityFunctions.get_connection() as cursor:
        for token_number in payload.token_number_arr:

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
                from_date, to_date = list(map(UtilityFunctions.get_date_obj, (from_str, to_str)))
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
                    calendar[date]["breakfast"] = payload.breakfast_time_slot or calendar[date]["breakfast"]
                    calendar[date]["lunch"] = payload.lunch_time_slot or calendar[date]["lunch"]
                    calendar[date]["dinner"] = payload.dinner_time_slot or calendar[date]["dinner"]
                    calendar[date]["is_suspended"] = payload.is_suspended if payload.is_suspended is not None else calendar[date]["is_suspended"]

                # If a date is not present in the database but is in the query then simply create the config using parameters
                else:
                    calendar[date] = {
                        "breakfast": payload.breakfast_time_slot,
                        "lunch": payload.lunch_time_slot,
                        "dinner": payload.dinner_time_slot,
                        "is_suspended": payload.is_suspended
                    }
            
            # Sort the dates (alrady in the database overlapping region)
            sorted_dates = sorted(calendar.keys())

            # List to carry new tuples to be inserted in the database
            new_intervals: List[tuple] = []

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
                            token_number,
                            UtilityFunctions.get_date_string(start_date),
                            UtilityFunctions.get_date_string(prev_date),
                            current_config["breakfast"], current_config["lunch"],
                            current_config["dinner"], current_config["is_suspended"]
                        ))

                        start_date = current_date
                        prev_date = current_date
                        current_config = calendar[start_date]
                    
                # Append the last interval block (that was left)
                new_intervals.append((
                    token_number,
                    UtilityFunctions.get_date_string(start_date),
                    UtilityFunctions.get_date_string(prev_date),
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

        UtilityFunctions.invalidate_client_cache(cursor)
        return {"status": "success", "message": "New custom configurations applied!"}

@app.post("/api/change-course-interval")
def change_course_interval(payload: models.ChangeCourseIntervalPayload) -> Dict[str, str]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT token_id FROM physical_qr_tokens WHERE token_number = ANY(%s)", (payload.token_number_arr,))
        res = cursor.fetchall()
        if not res:
            raise HTTPException(status_code=404, detail="None of the token numbers is valid")
        
        token_id_arr = [row[0] for row in res]
    
        cursor.execute('''
                    UPDATE trainee_assignments SET
                    course_end_date = COALESCE(%s, course_end_date)
                    WHERE token_id = ANY(%s) AND is_active = 1
                    ''', (payload.new_end_date, token_id_arr)
                    )
        UtilityFunctions.invalidate_client_cache(cursor)
        return {"status": "success", "message": f"Course Duration updated successfully for {len(token_id_arr)} trainees"}

@app.post("/api/unassign-tokens")
def take_back_token_from_trainee(payload: models.UnassignTokenPayload):
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT token_id FROM physical_qr_tokens WHERE token_number = ANY(%s)", (payload.token_number_arr,))
        res = cursor.fetchall()

        if not res:
            raise HTTPException(status_code=404, detail="None of the token numbers is valid!")
        
        token_id_list = [row[0] for row in res]
        cursor.execute("SELECT assignment_id FROM trainee_assignments WHERE token_id = ANY(%s) AND is_active = 1", (token_id_list,))
        res = cursor.fetchall()

        if not res:
            raise HTTPException(status_code=404, detail="Token numbers not assigned to anyone!")
        
        assignment_id_list = [row[0] for row in res]
        cursor.execute("UPDATE trainee_assignments SET is_active = 0 WHERE assignment_id = ANY(%s)", (assignment_id_list,))
        cursor.execute("UPDATE physical_qr_tokens SET card_status = 'AVAILABLE' WHERE token_id = ANY(%s)", (token_id_list,))

        return {"status": "success", "message": f"Succssfully unassigned {len(assignment_id_list)} trainees!"}

@app.post("/api/destroy-token")
def destroy_wasted_token(payload: models.DestroyTokenPayload) -> Dict[str, str]:
    with UtilityFunctions.get_connection() as cursor:
        cursor.execute("SELECT token_id, card_status FROM physical_qr_tokens WHERE token_number = %s", (payload.token_number,))
        res = cursor.fetchone()

        if not res:
            raise HTTPException(status_code=404, detail="Invalid Token Number!")
        
        token_id, card_status = res
        if card_status == "ASSIGNED":
            if payload.replaced_token_number is None:
                raise HTTPException(status_code=422, detail="Token is assigned to a trainee, and needs another token to substitute!")
            cursor.execute(
                """
                SELECT token_id FROM physical_qr_tokens
                WHERE token_number = %s AND card_status = 'AVAILABLE'
                """, (payload.replaced_token_number,)
            )
            res = cursor.fetchone()

            if not res:
                raise HTTPException(status_code=404, detail="The Substitute Token is not available for assignment!")
            
            replaced_token_id = res[0]
            cursor.execute(
                "UPDATE trainee_assignments SET token_id = %s WHERE token_id = %s AND is_active = 1",
                (replaced_token_id, token_id)
            )
            cursor.execute("UPDATE physical_qr_tokens SET card_status = 'ASSIGNED' WHERE token_id = %s", (replaced_token_id,))
            cursor.execute(
                "UPDATE special_config SET token_number = %s WHERE token_number = %s",
                (payload.replaced_token_number, payload.token_number)
            )
        
        cursor.execute("DELETE FROM physical_qr_tokens WHERE token_number = %s", (payload.token_number,))

        UtilityFunctions.invalidate_client_cache(cursor)
        return {"status": "success", "message": f"Successfully removed Token No. ({payload.token_number}) from database!"}

@app.post("/api/sync-nudge")
def send_updates_if_any(payload: models.SyncNudgePayload) -> Dict[str, Any]:
    last_sync_time = datetime.fromisoformat(payload.last_sync_str)
    current_datetime = UtilityFunctions.get_current_ist_datetime()
    current_time_str = current_datetime.isoformat()

    with UtilityFunctions.get_connection() as cursor:
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

        if payload.scans is not None:
            scan_data = [
                (scan.assignment_id, scan.date, scan.time, scan.meal_type)
                for scan in payload.scans
            ]
            query = """
                        INSERT INTO qr_scans (assignment_id, scan_date, scan_time, meal_type)
                        VALUES %s
                        ON CONFLICT (assignment_id, scan_date, scan_time) DO NOTHING;
                    """
            execute_values(cursor, query, scan_data)
    
    with UtilityFunctions.get_connection() as cursor:
        # Trainee or tokens updated after last sync
        if last_updated_time > last_sync_time:
            cursor.execute("SELECT key, value FROM settings WHERE key LIKE '%_time_slot' OR key = 'only_veg_days'")
            settings = {key: value for key, value in cursor.fetchall()}
            
            cursor.execute(
                '''SELECT
                    t.assignment_id,
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
                    "assignment_id": assignment_id,
                    "token_number": token_number,
                    "token_id": token_id,
                    "trainee_name": name,
                    "trainee_desg": desg,
                    "course_start_date": start,
                    "course_end_date": end,
                    "meal_preference": preference
                }
                for assignment_id, token_number, token_id, name, desg, start, end, preference in cursor.fetchall()
            ]

            cursor.execute(
                '''
                    SELECT token_number, from_date, to_date, breakfast_time_slot,
                    lunch_time_slot, dinner_time_slot, is_suspended
                    FROM special_config WHERE to_date >= %s
                ''', (UtilityFunctions.get_date_string(current_datetime),)
            )
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

            cursor.execute(
                '''
                    SELECT assignment_id, scan_date, scan_time, meal_type
                    FROM qr_scans WHERE scan_date = %s
                ''', (UtilityFunctions.get_date_string(current_datetime),)
            )
            scans = [
                {
                    "assignment_id": a_id,
                    "scan_date": s_date,
                    "scan_time": s_time,
                    "meal_type": meal
                }
                for a_id, s_date, s_time, meal in cursor.fetchall()
            ]

            return {
                "status": "synced_now",
                "server_sync_time": current_time_str,
                "assignments": assignments,
                "settings": settings,
                "exceptions": exceptions,
                "scans": scans
            }
        
        return {"status": "up_to_date", "server_sync_time": current_time_str}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("LISTEN_PORT")))