from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    MPGS_BASE_URL: str = ""
    MPGS_MERCHANT_ID: str = ""
    MPGS_API_KEY: str = ""
    IPQS_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    REDIS_URL: str = "redis://localhost:6379"
    DATABASE_URL: str = "postgresql+asyncpg://moofwd:moofwd@localhost:5432/moofwdguard"
    DECISION_APPROVE_THRESHOLD: float = 30.0
    DECISION_DECLINE_THRESHOLD: float = 65.0

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


def get_settings() -> Settings:
    return Settings()
