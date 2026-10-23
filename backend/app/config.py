import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[2] / ".env")
BASE_DIR=Path(__file__).resolve().parent.parent
APP_ENV=os.getenv('APP_ENV','development')
DATABASE_URL=os.getenv('DATABASE_URL',f'sqlite:///{BASE_DIR / "scamsathi.db"}')
CORS_ORIGINS=[x.strip() for x in os.getenv('CORS_ORIGINS','http://localhost:5173,http://127.0.0.1:5173').split(',') if x.strip()]
MAX_UPLOAD_BYTES=int(os.getenv('MAX_UPLOAD_BYTES','5242880'))
DEFAULT_STORE_RAW_CONTENT=os.getenv('DEFAULT_STORE_RAW_CONTENT','false').lower()=='true'
RETENTION_DAYS=int(os.getenv('RETENTION_DAYS','30'))
SAFE_BROWSING_API_KEY=os.getenv('SAFE_BROWSING_API_KEY','').strip()
OLLAMA_BASE_URL=os.getenv('OLLAMA_BASE_URL','http://127.0.0.1:11434').rstrip('/')
OLLAMA_MODEL=os.getenv('OLLAMA_MODEL','qwen2.5:3b').strip()
OLLAMA_TIMEOUT_SECONDS=float(os.getenv('OLLAMA_TIMEOUT_SECONDS','45'))
ARTIFACT_DIR=BASE_DIR/'ml'/'artifacts'
