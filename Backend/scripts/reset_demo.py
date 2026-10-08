import os
import sys

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.seed_demo import seed_database

if __name__ == "__main__":
    print("Resetting CYBERSCOPE demo database to initial state...")
    seed_database()
    print("Reset complete.")
