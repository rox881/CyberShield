from pydantic_settings import BaseSettings
import os

class Settings(BaseSettings):
    ollama_base_url: str = "http://localhost:11434"
    primary_model: str = "mistral:7b"
    fast_model: str = "phi3:mini"
    safe_browsing_key: str = ""
    port: int = 8000

    # Make DB path absolute relative to project root
    db_path: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "phishguard.db"))

    # Score thresholds
    threshold_safe: int = 35        # below this → safe  (was 40)
    threshold_suspicious: int = 75  # above this → threat (was 70)

    # Feature flags
    use_sandbox: bool = False
    use_safe_browsing: bool = False
    use_clustering: bool = True

    class Config:
        env_file = ".env"


settings = Settings()