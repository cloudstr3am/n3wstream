from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    s2_access_token: str = ""
    s2_account_endpoint: str = "https://aws.s2.dev/v1"
    s2_basin: str = "newstream"

    api_master_key: str = "changeme"
    db_path: str = "newstream.db"

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
