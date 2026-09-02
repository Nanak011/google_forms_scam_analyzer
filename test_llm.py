from google import genai

from app.config import settings

client = genai.Client(api_key=settings.gemini_api_key)

response = client.models.generate_content(
    model="gemini-3.6-flash",
    contents="Reply with exactly one word: pong",
)

print(response.text)