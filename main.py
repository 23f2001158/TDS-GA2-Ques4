
import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-p1ljwil9.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
PASTE_THE_COMPLETE_ASSIGNED_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----"""


class TokenRequest(BaseModel):
    token: str


@app.post("/verify")
def verify_token(request: TokenRequest):
    try:
        claims = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iss", "aud", "sub"],
            },
        )

        result = {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
        }

        return result

    except jwt.PyJWTError:
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )
