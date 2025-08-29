# ScamShieldAI

## 🚀 Deploying to Render

1. **Fork/clone this repo.**
2. **Generate `requirements.txt` from `pyproject.toml`** (or use the one included).
3. **Add a `Procfile`** with this line:
   ```
   web: python main.py
   ```
4. **Upload `firebase_creds.json`** as a Secret File in the Render dashboard.
5. **Set environment variables:**
   - `GEMINI_API_KEY`
   - `WHOIS_API_KEY`
   - `GOOGLE_SAFE_API_KEY`
6. **Deploy!**  
   Render will build and start your Flask app at your chosen URL.

## Local Development

1. `pip install -r requirements.txt`
2. Add a `.env` file with your API keys.
3. Run with `python main.py`