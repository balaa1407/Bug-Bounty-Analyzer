from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Bug Bounty Vulnerability Report Analyzer"
    mongo_uri: str = "mongodb://mongodb:27017"
    mongo_db: str = "bug_bounty"
    mongo_collection: str = "reports"
    max_pdf_size_mb: int = 10
    max_image_size_mb: int = 5

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
