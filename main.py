
import logging
import jwt

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-p1ljwil9.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
PASTE_YOUR_COMPLETE_ASSIGNED_PUBLIC_KEY_HERE
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

        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
        }

    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
    except jwt.InvalidAudienceError:
        logger.warning("Audience mismatch")
    except jwt.InvalidIssuerError:
        logger.warning("Issuer mismatch")
    except jwt.InvalidSignatureError:
        logger.warning("Signature mismatch: check the public key")
    except jwt.PyJWTError as exc:
        logger.warning("JWT verification failed: %s", exc)

    return JSONResponse(
        status_code=401,
        content={"valid": False},
    )
