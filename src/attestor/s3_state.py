import json
from typing import Any, Dict, Optional

from botocore.exceptions import ClientError

from attestor import aws_clients


class S3State:
    def __init__(self, bucket: str, prefix: str, region: str) -> None:
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.region = region
        self.client = aws_clients.client("s3", region)

    def _key(self, suffix: str) -> str:
        return f"{self.prefix}/{suffix}" if self.prefix else suffix

    def read_state(self) -> Optional[Dict[str, Any]]:
        key = self._key("state/latest.json")
        return self._read_json(key)

    def write_state(self, snapshot: Dict[str, Any]) -> None:
        key = self._key("state/latest.json")
        self._write_json(key, snapshot)

    def read_exceptions(self) -> Dict[str, Any]:
        key = self._key("config/exceptions.json")
        return self._read_json(key) or {"suppressions": []}

    def write_report(self, report_json: Dict[str, Any], report_pdf: bytes, year_month: str) -> None:
        json_key = self._key(f"reports/{year_month}/report.json")
        pdf_key = self._key(f"reports/{year_month}/report.pdf")
        self._write_json(json_key, report_json)
        self.client.put_object(Bucket=self.bucket, Key=pdf_key, Body=report_pdf, ContentType="application/pdf")

    def _read_json(self, key: str) -> Optional[Dict[str, Any]]:
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
            content = response["Body"].read().decode("utf-8")
            return json.loads(content)
        except ClientError:
            return None

    def _write_json(self, key: str, data: Dict[str, Any]) -> None:
        body = json.dumps(data, indent=2)
        self.client.put_object(Bucket=self.bucket, Key=key, Body=body.encode("utf-8"), ContentType="application/json")
