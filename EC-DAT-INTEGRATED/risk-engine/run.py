"""
Entry point. Run with:  python3 run.py
Serves the API at http://localhost:5000
"""
from app.api import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
