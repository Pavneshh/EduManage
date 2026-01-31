import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="pAvNeSh22",   # apna password daalo
        database="flask_db"
    )
