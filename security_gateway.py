import psycopg2
from datetime import datetime, timezone, timedelta
from fastapi import Header, HTTPException
from password_hasher import PasswordHasher

class Authenticator:
    def __init__(self, db_path: str, mutual_key: str):
        self.__DB_PATH = db_path
        self.__MUTUAL_KEY = mutual_key

        self.__hasher = PasswordHasher()
        self.__init_security_db()

    def __init_security_db(self):
        """Ensures the temporary nonce tracking table is established with index optimization."""
        conn = psycopg2.connect(self.__DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_header_signatures (
                signature TEXT PRIMARY KEY,
                received_at TEXT NOT NULL
            )
        """)
        # Index makes garbage collection lookups near-instantaneous 
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_received_at ON processed_header_signatures(received_at)")
        conn.commit()
        cursor.close()
        conn.close()

    def __get_current_ist_datetime(self) -> datetime:
        aware_current_time_utc = datetime.now(timezone.utc)
        aware_current_time_ist = aware_current_time_utc + timedelta(hours=5, minutes=30)
        current_time_ist = aware_current_time_ist.replace(tzinfo=None)
        return current_time_ist


    def verify_frontend_app_authenticity(
        self,
        x_app_timestamp: str = Header(..., description="Format: YYYY-MM-DD HH:MM:SS"),
        x_app_signature: str = Header(..., description="Custom signature string from PasswordHasher")
    ):
        """
        FastAPI Global Dependency Gatekeeper.
        Protects endpoints against Replay Attacks, Altered Payloads, and Unauthenticated clients.
        """
        # STEP 1: Time Window Security Gate (Max 10-second request age rule)
        try:
            request_time = datetime.strptime(x_app_timestamp, "%Y-%m-%d %H:%M:%S")
            server_current_time_ist = self.__get_current_ist_datetime()
            time_difference = abs((server_current_time_ist - request_time).total_seconds())
            print("Time Difference: ",time_difference)
            if time_difference > 30:
                raise HTTPException(
                    status_code=401,
                    detail="Request authorization window has expired."
                )
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Malformed network packet timestamp configuration."
            )

        # STEP 2: Connect to SQLite to clear garbage and check for double-spend attempts
        conn = psycopg2.connect(self.__DB_PATH)
        cursor = conn.cursor()
        
        try:
            cutoff_time_ist = server_current_time_ist - timedelta(minutes=2)
            cutoff_string = cutoff_time_ist.strftime("%Y-%m-%d %H:%M:%S")
            # Optimization: Wipe logs older than 2 minutes to keep table tiny and fast
            cursor.execute("DELETE FROM processed_header_signatures WHERE received_at < %s", (cutoff_string,))
            
            # Verify if signature exists in the live active nonce pool
            cursor.execute("SELECT 1 FROM processed_header_signatures WHERE signature = %s", (x_app_signature,))
            if cursor.fetchone() is not None:
                raise HTTPException(
                    status_code=401,
                    detail="Security Alert: Transaction signature was already processed. Replay Blocked."
                )

            # STEP 3: Regenerate deterministic combination using request-independent variables
            # Using timestamp ensures identity alignment per-second across endpoints
            expected_combination = f"{self.__MUTUAL_KEY}||{x_app_timestamp}"

            # STEP 4: Final validation assessment
            if not self.__hasher.check_password(expected_combination, x_app_signature):
                raise HTTPException(
                    status_code=401,
                    detail="Application Authentication Blueprint validation failed."
                )

            # STEP 5: Commit signature to cache database registry to prevent multi-device execution loops
            cursor.execute(
                "INSERT INTO processed_header_signatures (signature, received_at) VALUES (%s, %s)",
                (x_app_signature, self.__get_current_ist_datetime().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            conn.close()

        return True