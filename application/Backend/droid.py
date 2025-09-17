"""
droid.py - The AI Agent
This module contains the RillerDroid class, which represents
the adaptive AI assistant for each user, using MongoDB for profile storage.
"""
import logging
from datetime import datetime
from pymongo import MongoClient
from innovations import KillSwitch

class RillerDroid:
    """The personalized, adaptive AI assistant."""
    def __init__(self, user_id, mongo_uri):
        self.user_id = user_id
        self.adaptability = 0
        self.kill_switch = KillSwitch()
        self.user_profile = { 'likes': [], 'dislikes': [], 'habits': [], 'financial_goals': [] }
        try:
            self.client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            self.db = self.client["r3al3r_db"]
            self.profiles = self.db["user_profiles"]
            logging.info(f"RillerDroid for user {self.user_id} connected to MongoDB.")
        except Exception as e:
            logging.error(f"RillerDroid MongoDB connection failed: {e}")
            raise

    def adapt_to_user(self, user_data):
        """Adapts the droid's internal user profile based on user interactions."""
        if self.kill_switch.is_active():
            raise RuntimeError("Kill switch active, adaptation is disabled.")
        if self.adaptability < 5:
            self.adaptability += 1
        if isinstance(user_data, dict) and "intent" in user_data:
            intent = user_data["intent"]
            if intent == "personalize":
                entities = user_data.get("entities", [])
                self.user_profile['likes'].extend([e["value"] for e in entities if e.get("entity") == "like"])
                self.user_profile['dislikes'].extend([e["value"] for e in entities if e.get("entity") == "dislike"])
        try:
            self.profiles.update_one({"user_id": self.user_id}, {"$set": self.user_profile}, upsert=True)
            logging.info(f"RillerDroid adapted for user {self.user_id}.")
        except Exception as e:
            logging.error(f"Failed to update user profile for {self.user_id}: {e}")
            raise RuntimeError(f"Profile update failed: {e}")

