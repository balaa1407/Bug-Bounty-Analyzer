from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Bug Bounty Vulnerability Report Analyzer"
    mongo_uri: str = "mongodb://mongodb:27017"
    mongo_db: str = "bug_bounty"
    mongo_collection: str = "reports"
    max_pdf_size_mb: int = 10
    max_image_size_mb: int = 5
    admin_password_hash: str = "4b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e$a2e9ea9db715bc15c5d27c76867f81c7793a0513bf2118b6842d3568953f8c78"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
