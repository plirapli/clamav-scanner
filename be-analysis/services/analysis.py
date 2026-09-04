import json
from typing import Any

from openai import AsyncOpenAI

from core.config import get_settings

SYSTEM_PROMPT = (
    "Kamu adalah analis keamanan siber. Analisis data log deteksi virus dari ClamAV "
    "dan berikan rekomendasi mitigasi yang jelas dan praktis. Selalu jawab dalam "
    "Bahasa Indonesia."
)

ANALYZE_PROMPT = """Analisis log deteksi virus berikut:

{log}

Kembalikan JSON dengan format:
{{
  "risk_level": "low|medium|high|critical",
  "summary": "penjelasan singkat ancaman",
  "remediation": ["langkah mitigasi 1", "langkah mitigasi 2"],
  "recommendation": "rekomendasi tambahan"
}}"""

SUMMARY_PROMPT = """Berikut adalah {count} log infeksi terbaru:

{logs}

Kembalikan JSON dengan format:
{{
  "total_infected": "jumlah log",
  "top_virus": "virus yang paling banyak muncul",
  "trends": "ringkasan pola atau tren yang terlihat",
  "recommendations": ["rekomendasi perbaikan 1", "rekomendasi perbaikan 2"]
}}"""


class AnalysisService:
    def __init__(self) -> None:
        settings = get_settings()
        self.model = settings.OPENAI_MODEL
        self._client: AsyncOpenAI | None = (
            AsyncOpenAI(
                api_key=settings.OPENAI_API_KEY,
                base_url=settings.OPENAI_BASE_URL,
                default_headers={
                    "HTTP-Referer": "http://localhost:8000",
                    "X-Title": "BE Analysis",
                },
            )
            if settings.OPENAI_API_KEY
            else None
        )

    def _require_client(self) -> AsyncOpenAI:
        if self._client is None:
            raise RuntimeError("OPENAI_API_KEY belum dikonfigurasi")
        return self._client

    async def _complete_json(self, user_prompt: str) -> dict[str, Any]:
        client = self._require_client()
        response = await client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content or "{}"
        return json.loads(content)

    async def analyze_log(self, log: dict[str, Any]) -> dict[str, Any]:
        return await self._complete_json(
            ANALYZE_PROMPT.format(log=json.dumps(log, ensure_ascii=False))
        )

    async def summarize(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        payload = "\n".join(json.dumps(log, ensure_ascii=False) for log in logs)
        return await self._complete_json(
            SUMMARY_PROMPT.format(count=len(logs), logs=payload)
        )
