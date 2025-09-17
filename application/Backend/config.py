import os
# This is the line that was missing
from datetime import timedelta

class AppConfig:
    """
    Application configuration class.
    Best practice is to load sensitive data from environment variables.
    """
    
    # Get the value from an environment variable, or use a default if it's not set.
    SECRET_KEY = os.environ.get("SECRET_KEY", "wDy6mj6C8jCZHcxNdKG1GzgGvNoqmtxDdqlJmiLFmQ4")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "RZ28SlGU7rTQfz9wE5aCNA")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", "/home/ubuntu/r3aler-ai/data/realer_ai.db")
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://AKIAYMMREDMT2HP6MQ6O:kS%2Fjb0I0dEW2fQHlsMgVYYvq79GsSmMM3XZ9tznQ@cluster0.6h0w6hw.mongodb.net/")

    # Application Settings that are not sensitive
    ADAPTATION_COOLDOWN = 60
    MAX_INSIGHTS_BEFORE_REVIEW = 100
    JWT_EXPIRY_SECONDS = int(timedelta(hours=24).total_seconds())
    SOUL_KEY_VENDOR_ID = 0x1234
    SOUL_KEY_PRODUCT_ID = 0x5678