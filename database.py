import mysql.connector
from mysql.connector import Error
import traceback
import os

class DatabaseConnection:
    def __init__(self):
        self.connection = None
        self.cursor = None
        self.connect()

    def connect(self):
        """Establish a connection to the database with more robust error handling"""
        try:
            # Use environment variables or fallback to hardcoded values
            self.connection = mysql.connector.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                database=os.getenv('DB_NAME', 'your db name'),
                user=os.getenv('DB_USER', 'ecommerce_user'),
                password=os.getenv('DB_PASSWORD', 'your password'),
                auth_plugin='mysql_native_password'
            )
            
            if self.connection.is_connected():
                print("✅ Database connected successfully.")
                self.cursor = self.connection.cursor(dictionary=True)
            else:
                print("❌ Failed to connect to database.")
                raise Exception("Database connection failed")
        
        except Error as e:
            print(f"❌ Database Connection Error: {e}")
            print(traceback.format_exc())
            raise

    def execute_query(self, query, params=None):
        """Execute INSERT, UPDATE, DELETE queries"""
        try:
            self.cursor.execute(query, params)
            self.connection.commit()
            return True
        except Error as e:
            print(f"❌ MySQL Error: {e}")
            self.connection.rollback()
            return False

    def fetch_all(self, query, params=None):
        """Fetch multiple rows from a SELECT query"""
        try:
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except Error as e:
            print(f"❌ Fetch Error: {e}")
            return []

    def fetch_one(self, query, params=None):
        
        """Fetch one result from a query"""
        if self.connection is None or self.cursor is None:
            print("❌ Database connection is not established.")
            return None
        try:
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            result = self.cursor.fetchone()
            print(f"✅ Fetch One Result: {result}")  # ✅ Debugging Step
            return result
        except Error as e:
            print(f"❌ Error fetching data: {e}")
            return None

    def close(self):
        """Close the database connection"""
        if self.connection.is_connected():
            self.cursor.close()
            self.connection.close()
            print("✅ MySQL connection closed.")
# Utility function for password hashing
import hashlib

def hash_password(password):
    """
    Hash a password using SHA-256
    """
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_password, provided_password):
    """
    Verify a stored password against one provided by user
    """
    return stored_password == hash_password(provided_password)
