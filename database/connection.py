
from sqlalchemy import create_engine,text
import os

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)

def test_connection():


  with engine.connect() as connection:
    result = connection.execute(text("SELECT version();"))
    print(result.fetchone())
