# db_handler.py
import psycopg2
import streamlit as st

def get_db_connection():
    """Establish a connection to the Neon PostgreSQL database."""
    conn = psycopg2.connect(st.secrets["neon"]["db_url"])
    return conn

def run_query(query, params=None):
    """Run a SELECT query and return all results."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    results = cur.fetchall()
    cur.close()
    conn.close()
    return results

def run_command(query, params=None):
    """Run an INSERT/UPDATE/DELETE command."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    conn.commit()
    cur.close()
    conn.close()
