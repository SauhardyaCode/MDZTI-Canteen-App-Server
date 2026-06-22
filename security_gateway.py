import psycopg2
import time
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
            CREATE TABLE IF NOT EXISTS processed_app_nonces (
                nonce TEXT PRIMARY KEY,
                received_at_ms BIGINT NOT NULL
            )
        """)
        # Index makes garbage collection lookups near-instantaneous 
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_received_at_ms ON processed_app_nonces(received_at_ms)")
        conn.commit()
        cursor.close()
        conn.close()

    def verify_frontend_app_authenticity(
        self,
        x_app_timestamp: str = Header(..., description="Format: Epoch Milliseconds String"),
        x_app_nonce: str = Header(..., description="Cryptographically unique random nonce hex"),
        x_app_signature: str = Header(..., description="Custom signature string from PasswordHasher")
    ):
        """
        FastAPI Global Dependency Gatekeeper.
        Protects endpoints against Replay Attacks, Altered Payloads, and Unauthenticated clients.
        """
        try:
            current_time_ms = int(time.time() * 1000)
            request_time_ms = int(x_app_timestamp)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Malformed network packet timestamp configuration."
            )
        
        time_difference_ms = abs(current_time_ms - request_time_ms)
        print("Time Difference (sec): ", time_difference_ms/1000)
        
        if time_difference_ms > (30 * 1000): # 30 seconds threshold
            raise HTTPException(
                status_code=401,
                detail="Request authorization window has expired."
            )

        conn = psycopg2.connect(self.__DB_PATH)
        cursor = conn.cursor()
        
        try:
            # Optimization: Wipe logs older than 2 minutes to keep table tiny and fast
            cutoff_time_ms = current_time_ms - (2 * 60 * 1000)
            cursor.execute("DELETE FROM processed_app_nonces WHERE received_at_ms < %s", (cutoff_time_ms,))
            
            # Verify if signature exists in the live active nonce pool
            cursor.execute("SELECT 1 FROM processed_app_nonces WHERE nonce = %s", (x_app_nonce,))
            if cursor.fetchone() is not None:
                raise HTTPException(
                    status_code=401,
                    detail="Security Alert: Transaction signature was already processed. Replay Blocked."
                )

            expected_combination = f"{self.__MUTUAL_KEY}||{x_app_timestamp}||{x_app_nonce}"

            # Final validation assessment
            if not self.__hasher.check_password(expected_combination, x_app_signature):
                raise HTTPException(
                    status_code=401,
                    detail="Application Authentication Blueprint validation failed."
                )

            # Burn the nonce so it can never be used (inside 2 mins)
            cursor.execute(
                "INSERT INTO processed_app_nonces (nonce, received_at_ms) VALUES (%s, %s)",
                (x_app_nonce, current_time_ms)
            )
            conn.commit()
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            cursor.close()
            conn.close()

        return True