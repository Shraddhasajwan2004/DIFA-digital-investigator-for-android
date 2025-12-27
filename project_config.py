# config.py

from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file

VT_API_KEY = os.getenv("VT_API_KEY")

