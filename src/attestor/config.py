from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Config:
    bucket: str
    prefix: str
    region: str

    @staticmethod
    def from_env() -> "Config":
        bucket = os.getenv("ATT_BUCKET")
        prefix = os.getenv("ATT_PREFIX", "ghost-utility")
        region = os.getenv("ATT_REGION", os.getenv("AWS_REGION", "us-east-1"))
        if not bucket:
            raise ValueError("ATT_BUCKET environment variable is required")
        return Config(bucket=bucket, prefix=prefix, region=region)
