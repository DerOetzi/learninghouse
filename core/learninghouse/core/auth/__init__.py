from datetime import datetime, timedelta, timezone
from functools import lru_cache

import jwt
from fastapi import APIRouter, Depends, Path, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.security.api_key import APIKeyHeader, APIKeyQuery

from learninghouse.core.auth.errors import InvalidPassword
from learninghouse.core.auth.models import (
    APIKey,
    APIKeyInfo,
    APIKeyRequest,
    APIKeyRole,
    LoginRequest,
    PasswordRequest,
    SecurityDatabase,
    Token,
    TokenPayload,
    UserRole,
)
from learninghouse.core.errors.models import (
    LearningHouseSecurityException,
    LearningHouseUnauthorizedException,
)
from learninghouse.core.logger import logger
from learninghouse.core.settings import service_settings

settings = service_settings()

API_KEY_NAME = "X-LEARNINGHOUSE-API-KEY"

api_key_query = APIKeyQuery(name="api_key", auto_error=False)
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
jwt_bearer = HTTPBearer(bearerFormat="JWT", auto_error=False)


INITIAL_PASSWORD_WARNING = """
In order to activate the service you have to replace the fallback password.

See https://github.com/LearningHouseService/learninghouse-monorepo/tree/main/learninghouse#fallback-password
"""


class AuthServiceInternal:
    def __init__(self):
        self.database = SecurityDatabase.load_or_write_default()
        self.refresh_tokens: dict[str, datetime] = {}

    @property
    def is_initial_admin_password(self) -> bool:
        return self.database.initial_password

    def create_token(self, password: str) -> Token:
        if not self.database.authenticate_password(password):
            raise InvalidPassword()

        self.cleanup_refresh_tokens()
        token = self.create_new_token()

        logger.info("Admin user logged in sucessfully")

        return token

    def refresh_token(self, refresh_token_jti: str) -> Token:
        self.cleanup_refresh_tokens()

        if refresh_token_jti in self.refresh_tokens:
            del self.refresh_tokens[refresh_token_jti]

        token = self.create_new_token()

        logger.info("Admin token refreshed")

        return token

    def revoke_refresh_token(self, refresh_token_jti: str | None) -> bool:
        self.cleanup_refresh_tokens()

        if refresh_token_jti:
            if refresh_token_jti in self.refresh_tokens:
                del self.refresh_tokens[refresh_token_jti]

            logger.info("Logout admininstrator refresh token")

        return True

    def revoke_all_refresh_tokens(self) -> bool:
        self.refresh_tokens.clear()

        logger.warning("Revoked all refresh tokens")

        return True

    def cleanup_refresh_tokens(self):
        del_tokens = []
        for jti, expire in self.refresh_tokens.items():
            if expire < datetime.now(timezone.utc):
                del_tokens.append(jti)

        for jti in del_tokens:
            del self.refresh_tokens[jti]

    def create_new_token(self) -> Token:
        issuetime = datetime.now(timezone.utc)
        access_expire = issuetime + timedelta(minutes=1)
        access_payload = TokenPayload.create("admin", access_expire, issuetime)
        access_token = jwt.encode(
            access_payload.model_dump(), settings.jwt_secret, algorithm="HS256"
        )

        refresh_expire = issuetime + timedelta(minutes=settings.jwt_expire_minutes)
        refresh_payload = TokenPayload.create("refresh", refresh_expire, issuetime)
        refresh_token = jwt.encode(
            refresh_payload.model_dump(), settings.jwt_secret, algorithm="HS256"
        )

        self.refresh_tokens[refresh_payload.jti] = refresh_expire

        return Token(access_token=access_token, refresh_token=refresh_token)

    def update_password(self, old_password: str, new_password: str) -> bool:
        if not self.database.authenticate_password(old_password):
            raise InvalidPassword()

        self.database.update_password(new_password)
        self.database.write()
        self.refresh_tokens.clear()

        logger.info("New administration password set")

        return True

    def list_api_keys(self) -> list[APIKeyInfo]:
        return self.database.list_api_keys()

    def create_apikey(self, request: APIKeyRequest) -> APIKey:
        api_key = self.database.create_apikey(request)
        self.database.write()

        logger.info(f"New API key for {request.description} added")

        return api_key

    def delete_apikey(self, description: str) -> str:
        confirm = self.database.delete_apikey(description)
        self.database.write()

        logger.info(f"Removed API key for {description}.")

        return confirm

    async def protect_admin(
        self, credentials: HTTPAuthorizationCredentials = Security(jwt_bearer)
    ) -> UserRole:
        self.validate_credentials(credentials, True, "admin")
        return UserRole.ADMIN

    async def protect_refresh(
        self, credentials: HTTPAuthorizationCredentials = Security(jwt_bearer)
    ) -> str:
        _, jti = self.validate_credentials(credentials, True, "refresh")

        return jti

    async def get_refresh(
        self, credentials: HTTPAuthorizationCredentials = Security(jwt_bearer)
    ) -> str | None:
        is_valid, jti = self.validate_credentials(credentials, False, "refresh")

        return jti if is_valid else None

    async def protect_user(
        self,
        credentials: HTTPAuthorizationCredentials = Security(jwt_bearer),
        query: str = Security(api_key_query),
        header: str = Security(api_key_header),
    ) -> UserRole:
        role = self.is_admin_user_or_trainer(credentials, query, header)

        return role

    async def protect_trainer(
        self,
        credentials: HTTPAuthorizationCredentials = Security(jwt_bearer),
        query: str = Security(api_key_query),
        header: str = Security(api_key_header),
    ) -> UserRole:
        role = self.is_admin_user_or_trainer(credentials, query, header)

        if role.role not in ["admin", APIKeyRole.TRAINER.role]:
            raise LearningHouseUnauthorizedException()

        return role

    def is_admin_user_or_trainer(
        self, credentials: HTTPAuthorizationCredentials, query: str, header: str
    ) -> UserRole | None:
        role = None

        is_valid, _ = self.validate_credentials(credentials, False, "admin")

        if is_valid:
            role = UserRole.ADMIN
        else:
            key = query or header
            if not key:
                raise LearningHouseSecurityException("Invalid credentials")

            api_key_info = self.database.find_apikey_by_key(key)
            if not api_key_info:
                raise LearningHouseUnauthorizedException()

            role = UserRole.from_string(str(api_key_info.role))
        return role

    def validate_credentials(
        self,
        credentials: HTTPAuthorizationCredentials | None,
        auto_error: bool,
        subject: str,
    ) -> tuple[bool, str | None]:
        is_valid = True
        jti = None

        if credentials:
            if credentials.scheme != "Bearer":
                is_valid = False
                self.raise_error_conditionally(
                    "Invalid authentication scheme.", auto_error
                )

            verified, jti = self.verify_jwt(credentials.credentials, subject)

            if not verified:
                is_valid = False
                if auto_error:
                    raise LearningHouseUnauthorizedException()

        else:
            is_valid = False
            self.raise_error_conditionally("Invalid authorization code.", auto_error)

        return is_valid, jti

    @staticmethod
    def raise_error_conditionally(description: str, auto_error: bool):
        if auto_error:
            raise LearningHouseSecurityException(description)

    def verify_jwt(self, access_token: str, subject: str) -> tuple[bool, str | None]:
        verified = False
        jti = None

        payload_args = settings.jwt_payload_claims

        try:
            payload = TokenPayload(
                **jwt.decode(
                    access_token,
                    settings.jwt_secret,
                    algorithms=["HS256"],
                    audience=payload_args["audience"],
                    issuer=payload_args["issuer"],
                )
            )

            if not payload.verify_subject(subject):
                raise jwt.InvalidTokenError("Invalid subject")

            if subject == "refresh":
                verified = payload.jti in self.refresh_tokens and self.refresh_tokens[
                    payload.jti
                ] > datetime.now(timezone.utc)

                if not verified:
                    logger.error("No valid refresh token")
            else:
                verified = True

            jti = payload.jti
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as err:
            logger.info(err)

        return verified, jti


@lru_cache()
def auth_service_cached() -> AuthServiceInternal:
    service = AuthServiceInternal()
    return service


authservice = auth_service_cached()

auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post(
    "/token",
    responses={
        200: {"description": "Successfully retrieve token"},
        InvalidPassword.STATUS_CODE: InvalidPassword.api_description(),
    },
)
async def post_token(request: LoginRequest) -> Token:
    return authservice.create_token(request.password)


@auth_router.put("/token")
async def put_token(
    refresh_token_jti: str = Depends(authservice.protect_refresh),
) -> Token:
    return authservice.refresh_token(refresh_token_jti)


@auth_router.delete("/token")
async def delete_token(
    refresh_token_jti: str | None = Depends(authservice.get_refresh),
) -> bool:
    return authservice.revoke_refresh_token(refresh_token_jti)


router_protected = APIRouter(dependencies=[Depends(authservice.protect_admin)])


@router_protected.delete("/tokens")
async def delete_tokens() -> bool:
    return authservice.revoke_all_refresh_tokens()


@router_protected.put("/password")
async def update_password(
    request: PasswordRequest, _=Depends(authservice.protect_admin)
) -> bool:
    return authservice.update_password(request.old_password, request.new_password)


if not authservice.is_initial_admin_password:

    @router_protected.get("/apikeys")
    async def list_api_keys() -> list[APIKeyInfo]:
        return authservice.list_api_keys()

    @router_protected.post("/apikey")
    async def create_apikey(request: APIKeyRequest) -> APIKey:
        return authservice.create_apikey(request)

    @router_protected.delete("/apikey/{description}")
    async def delete_apikey(
        description: str = Path(
            min_length=3,
            max_length=15,
            regex=r"^[A-Za-z]\w{1,13}[A-Za-z0-9]$",
            example="app_as_user",
        )
    ) -> str:
        return authservice.delete_apikey(description)


auth_router.include_router(router_protected)


@auth_router.get("/role")
def get_role(user_role: UserRole = Depends(authservice.protect_user)) -> UserRole:
    return user_role
