"""OIDC authentication module for validating access tokens and DPoP proofs."""

import abc
import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from jwskate import Jwk, SignedJwt
from loguru import logger

from axa_fr_oidc.constants import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    DEFAULT_DPOP_MAX_AGE_SECONDS,
    DEFAULT_JTI_LIFETIME_SECONDS,
    DPOP_TOKEN_TYPE,
    ERROR_JWK_NOT_FOUND,
    OIDC_WELL_KNOWN_PATH,
    SUPPORTED_ALGORITHMS,
)
from axa_fr_oidc.http_service.http_service import IHttpServiceGet
from axa_fr_oidc.memory_cache.memory_cache import IMemoryCache


@dataclass
class AuthenticationResult:
    """Result of an authentication validation operation.

    Attributes:
        success: Whether the authentication was successful.
        error: Error message if authentication failed, empty string otherwise.
        payload: The decoded token payload if successful, None otherwise.
    """

    success: bool
    error: str = ""
    payload: dict[str, Any] | None = None


def find_jwk(jwks: dict[str, Any], jwt: SignedJwt) -> dict[str, Any] | None:
    """Find in the JWKS the key matching the 'kid' of the token (Access Token)."""
    jwk_key: dict[str, Any] | None = None
    jwks_keys: list[dict[str, Any]] = jwks["keys"]
    for key in jwks_keys:
        if key["kid"] == jwt.headers.get("kid"):
            jwk_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "alg": key["alg"],
                "n": key["n"],
                "e": key["e"],
            }
            break
    return jwk_key


class IOidcAuthentication(abc.ABC):
    """Abstract base class for OIDC authentication operations.

    This interface defines methods for token validation and endpoint discovery
    in both synchronous and asynchronous contexts.
    """

    @abc.abstractmethod
    async def get_token_endpoint_async(self) -> str:
        """Get the token endpoint URL asynchronously.

        Returns:
            The OAuth2 token endpoint URL.
        """
        ...

    @abc.abstractmethod
    def get_token_endpoint(self) -> str:
        """Get the token endpoint URL synchronously.

        Returns:
            The OAuth2 token endpoint URL.
        """
        ...

    @abc.abstractmethod
    async def validate_async(
        self,
        token: str,
        dpop: str | None,
        path: str | None = None,
        http_method: str | None = None,
    ) -> AuthenticationResult:
        """Validate an access token asynchronously.

        Args:
            token: The access token to validate.
            dpop: The DPoP proof JWT, or None if not using DPoP.
            path: The request path for DPoP validation.
            http_method: The HTTP method for DPoP validation.

        Returns:
            AuthenticationResult indicating success or failure.
        """
        ...

    @abc.abstractmethod
    def validate(
        self,
        token: str,
        dpop: str | None,
        path: str | None = None,
        http_method: str | None = None,
    ) -> AuthenticationResult:
        """Validate an access token synchronously.

        Args:
            token: The access token to validate.
            dpop: The DPoP proof JWT, or None if not using DPoP.
            path: The request path for DPoP validation.
            http_method: The HTTP method for DPoP validation.

        Returns:
            AuthenticationResult indicating success or failure.
        """
        ...

    @abc.abstractmethod
    def get_scopes(self) -> list[str]:
        """Get the list of required scopes.

        Returns:
            List of scope strings required for authentication.
        """
        ...


class OidcAuthentication(IOidcAuthentication):
    """OIDC authentication implementation for token validation.

    This class handles validation of OAuth2/OIDC access tokens and
    DPoP (Demonstrating Proof-of-Possession) proofs.

    The JWKS is cached indefinitely and only refreshed when token validation
    fails (e.g., when a signing key is not found). This follows the best practice
    of invalidating the cache and retrying once on failure.

    Attributes:
        service: HTTP service for fetching OIDC configuration.
        issuer: The expected token issuer URL.
        api_audience: The expected audience claim value.
        algorithms: List of allowed signing algorithms.
        scopes: List of required scopes.
        memory_cache: Cache for storing JWKS and token endpoints.
    """

    def __init__(
        self,
        issuer: str,
        scopes: list[str],
        api_audience: str | None,
        service: IHttpServiceGet,
        memory_cache: IMemoryCache,
        algorithms: list[str] | None = None,
        token_endpoint: str | None = None,
    ) -> None:
        """Initialize the OIDC authentication handler.

        Args:
            issuer: The expected token issuer URL.
            scopes: List of required scopes for validation.
            api_audience: The expected audience claim, or None to skip audience validation.
            service: HTTP service for fetching OIDC configuration.
            memory_cache: Cache instance for storing JWKS.
            algorithms: List of allowed signing algorithms, defaults to SUPPORTED_ALGORITHMS.
            token_endpoint: Explicit token endpoint URL. When provided, skips OIDC
                discovery for the token endpoint (JWKS is still discovered). Defaults
                to None (auto-discover from issuer).
        """
        if algorithms is None:
            algorithms = SUPPORTED_ALGORITHMS

        self.service = service
        self.issuer = issuer
        self.api_audience = api_audience
        self.algorithms = algorithms
        self.scopes = scopes
        self.cache_token_endpoint: str | None = token_endpoint
        self.memory_cache = memory_cache
        self.used_jti: dict[str, float] = {}
        self._explicit_token_endpoint = token_endpoint

    def _check_jti(self, jti: str, lifetime: int = DEFAULT_JTI_LIFETIME_SECONDS) -> bool:
        """Check if the jti is already used (replay).

        Returns True if it's OK, False if the jti is already present and not expired.

        :param jti: Unique identifier (DPoP claim).
        :param lifetime: Validity duration (in seconds) during which this
                         jti is blocked. Default is 5 minutes.
        :return: bool
        """
        now = time.time()

        # 1) Clean expired jti before checking
        expired_jti = []
        for stored_jti, expiration_time in self.used_jti.items():
            if expiration_time < now:
                expired_jti.append(stored_jti)
        for ej in expired_jti:
            del self.used_jti[ej]

        # 2) Check if this jti is already in the dict, and not expired
        if jti in self.used_jti:
            # => It's a replay, reject it
            return False

        # 3) Otherwise, add it, indicating an expiration date (now + lifetime)
        self.used_jti[jti] = now + lifetime
        return True

    def _get_cached_jwks(self) -> tuple[str, dict[str, Any]] | None:
        """Retrieve JWKS from cache if available.

        The cache is never expired by time; it is only invalidated when
        token validation fails and a retry is needed.

        Returns:
            A tuple of (token_endpoint, jwks) if cached, None otherwise.
        """
        cache_result: Any = self.memory_cache.get(("auth", self.issuer))

        if cache_result is not None:
            cached_token_endpoint: str
            cached_jwks: dict[str, Any]
            cached_token_endpoint, cached_jwks = cache_result
            self.cache_token_endpoint = cached_token_endpoint
            return (cached_token_endpoint, cached_jwks)

        return None

    def _invalidate_cache(self) -> None:
        """Invalidate the JWKS cache for the current issuer.

        This should be called when token validation fails due to a missing
        signing key, allowing a fresh JWKS to be fetched on retry.
        """
        self.memory_cache.delete(("auth", self.issuer))
        self.cache_token_endpoint = self._explicit_token_endpoint

    async def _get_jwks_async(self) -> tuple[dict[str, Any], str]:
        """Get JWKS and token endpoint asynchronously.

        Returns:
            A tuple of (jwks, token_endpoint).
        """
        cache_result = self._get_cached_jwks()

        if cache_result is not None:
            # Get it from cache
            cached_token_endpoint, cached_jwks = cache_result
            return cached_jwks, cached_token_endpoint

        # Get it from the well-known config
        wellknowurl = await self.service.get_async(self.issuer + OIDC_WELL_KNOWN_PATH)
        cache_jwks = await self.service.get_async(wellknowurl["jwks_uri"])
        token_endpoint: str = self._explicit_token_endpoint or wellknowurl["token_endpoint"]

        self.cache_token_endpoint = token_endpoint

        self.memory_cache.set(
            ("auth", self.issuer),
            (token_endpoint, cache_jwks),
        )

        return cache_jwks, token_endpoint

    def _get_jwks(self) -> tuple[dict[str, Any], str]:
        """Get JWKS and token endpoint synchronously.

        Returns:
            A tuple of (jwks, token_endpoint).
        """
        cache_result = self._get_cached_jwks()

        if cache_result is not None:
            # Get it from cache
            cached_token_endpoint, cached_jwks = cache_result
            return cached_jwks, cached_token_endpoint

        # Get it from the well-known config
        wellknowurl = self.service.get(self.issuer + OIDC_WELL_KNOWN_PATH)
        cache_jwks = self.service.get(wellknowurl["jwks_uri"])
        token_endpoint: str = self._explicit_token_endpoint or wellknowurl["token_endpoint"]

        self.cache_token_endpoint = token_endpoint

        self.memory_cache.set(
            ("auth", self.issuer),
            (token_endpoint, cache_jwks),
        )
        return cache_jwks, token_endpoint

    async def get_token_endpoint_async(self) -> str:
        """Get the token endpoint URL asynchronously.

        Returns:
            The OAuth2 token endpoint URL.
        """
        _, token_endpoint = await self._get_jwks_async()
        return token_endpoint

    def get_token_endpoint(self) -> str:
        """Get the token endpoint URL synchronously.

        Returns:
            The OAuth2 token endpoint URL.
        """
        _, token_endpoint = self._get_jwks()
        return token_endpoint

    def _validate_access_token(self, jwt: SignedJwt, jwks: dict[str, Any]) -> AuthenticationResult:
        """Validate the OIDC token / Access Token: signature, claims (scope, issuer, audience)."""
        try:
            jwk_key = find_jwk(jwks, jwt)
            if jwk_key is None:
                return AuthenticationResult(success=False, error=ERROR_JWK_NOT_FOUND)

            if jwt.headers.get("alg", "").upper() not in self.algorithms:
                return AuthenticationResult(success=False, error="Wrong algorithm used")

            payload: dict[str, Any] = jwt.claims
            # Check scopes
            token_scopes = payload.get("scope", "").split(" ")
            for scope in self.scopes:
                if scope not in token_scopes:
                    return AuthenticationResult(success=False, error=f"Scope '{scope}' not found")

            # Standard validation (exp, iss, aud, etc.)
            if not self.api_audience:
                # Without audience
                jwt.validate(jwk_key, issuer=self.issuer)
            else:
                # With audience
                logger.debug(f"audience validation: issuer : {self.issuer} and audience: {self.api_audience}")
                jwt.validate(jwk_key, issuer=self.issuer, audience=self.api_audience)

            return AuthenticationResult(success=True, payload=payload)

        except Exception as e:
            return AuthenticationResult(success=False, error=str(e))

    def _compute_jwk_thumbprint(self, jwk: dict[str, Any]) -> str:
        """Compute the JWK thumbprint according to RFC 7638."""
        canonical_jwk = {
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"],
        }
        jwk_json = json.dumps(canonical_jwk, separators=(",", ":"), sort_keys=True)
        hash_bytes = hashlib.sha256(jwk_json.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")

    def _validate_dpop_header(self, dpop_jwt: SignedJwt) -> AuthenticationResult | Jwk:
        """Validate DPoP JWT header and extract the public key.

        Args:
            dpop_jwt: The DPoP JWT to validate.

        Returns:
            The public key (Jwk) if valid, or AuthenticationResult with error.
        """
        # Verify that the 'typ' header = 'dpop+jwt'
        typ = dpop_jwt.headers.get("typ")
        if typ != DPOP_TOKEN_TYPE:
            return AuthenticationResult(success=False, error=f"Invalid 'typ' header (expected: {DPOP_TOKEN_TYPE})")

        # Get the public key from the 'jwk' header
        jwk_header = dpop_jwt.headers.get("jwk")
        if not jwk_header:
            return AuthenticationResult(success=False, error="No 'jwk' in DPoP header")

        # Build a Jwk object to verify the signature
        public_key = Jwk(jwk_header)
        dpop_jwt.verify_signature(public_key, alg=dpop_jwt.alg)

        return public_key

    def _validate_dpop_claims(self, claims: dict[str, Any], path: str, http_method: str) -> AuthenticationResult | None:
        """Validate DPoP claims (htm, htu, iat, jti).

        Args:
            claims: The DPoP JWT claims.
            path: Expected request path.
            http_method: Expected HTTP method.

        Returns:
            AuthenticationResult with error if invalid, None if valid.
        """
        # Verify the presence of required fields
        for required in ["htm", "htu", "iat", "jti"]:
            if required not in claims:
                return AuthenticationResult(success=False, error=f"Missing DPoP claim: '{required}'")

        # Verify consistency between expected HTTP method and 'htm'
        if claims["htm"].lower() != http_method.lower():
            return AuthenticationResult(
                success=False,
                error=f"DPoP method '{claims['htm']}' does not match '{http_method}'",
            )

        # Verify (simplified) that the DPoP path contains or ends with 'path'
        if not claims["htu"].endswith(path):
            return AuthenticationResult(
                success=False,
                error=f"DPoP path '{claims['htu']}' does not match '{path}'",
            )

        # Verify iat timing
        now = time.time()
        iat = claims["iat"]
        if iat > now + DEFAULT_CLOCK_SKEW_SECONDS:
            return AuthenticationResult(success=False, error="DPoP 'iat' is too far in the future")

        if iat < (now - DEFAULT_DPOP_MAX_AGE_SECONDS):
            return AuthenticationResult(success=False, error="DPoP has expired or is too old")

        return None

    def _validate_dpop_binding(
        self, claims: dict[str, Any], jwk_header: dict[str, Any], access_token: str
    ) -> AuthenticationResult | None:
        """Validate DPoP token binding (ath and jkt).

        Args:
            claims: The DPoP JWT claims.
            jwk_header: The JWK from the DPoP header.
            access_token: The access token to validate against.

        Returns:
            AuthenticationResult with error if invalid, None if valid.
        """
        # Validate access token hash (ath)
        sha256_digest = hashlib.sha256(access_token.encode("ascii")).digest()
        expected_ath = base64.urlsafe_b64encode(sha256_digest).rstrip(b"=").decode("ascii")
        if claims.get("ath") != expected_ath:
            return AuthenticationResult(
                success=False,
                error="DPoP 'ath' hash does not match the Access Token",
            )

        # Validate JWK thumbprint (jkt)
        access_token_jwt = SignedJwt(access_token)
        cnf = access_token_jwt.claims.get("cnf", {})
        expected_jkt = cnf.get("jkt")
        if not expected_jkt:
            return AuthenticationResult(success=False, error="Access token does not contain 'cnf.jkt'")

        computed_jkt = self._compute_jwk_thumbprint(jwk_header)
        if computed_jkt != expected_jkt:
            return AuthenticationResult(
                success=False,
                error="DPoP JWK thumbprint does not match 'cnf.jkt' of the access token",
            )

        return None

    def _validate_dpop(self, dpop_token: str, path: str, http_method: str, access_token: str) -> AuthenticationResult:
        """Validate the DPoP token.

        Args:
            dpop_token: The DPoP JWT.
            path: Expected path (e.g., "/api/resource").
            http_method: Expected HTTP method (e.g., "GET", "POST").
            access_token: The access token to validate against.

        Returns:
            AuthenticationResult indicating success or failure.
        """
        if not dpop_token:
            return AuthenticationResult(success=False, error="No DPoP token provided")

        try:
            dpop_jwt = SignedJwt(dpop_token)

            # Validate header and get public key
            header_result = self._validate_dpop_header(dpop_jwt)
            if isinstance(header_result, AuthenticationResult):
                return header_result

            claims = dpop_jwt.claims
            jwk_header: dict[str, Any] = dpop_jwt.headers["jwk"]  # Safe: validated in _validate_dpop_header

            # Validate claims
            claims_result = self._validate_dpop_claims(claims, path, http_method)
            if claims_result is not None:
                return claims_result

            # Validate token binding
            binding_result = self._validate_dpop_binding(claims, jwk_header, access_token)
            if binding_result is not None:
                return binding_result

            # Anti-Replay verification
            jti = claims["jti"]
            if not self._check_jti(jti, lifetime=DEFAULT_JTI_LIFETIME_SECONDS):
                return AuthenticationResult(success=False, error="DPoP Replay detected: jti already used.")

            return AuthenticationResult(success=True, payload=claims)

        except Exception as e:
            return AuthenticationResult(success=False, error=str(e))

    def _validate_token_and_dpop(
        self,
        token: str,
        jwks: dict[str, Any],
        dpop: str | None,
        path: str | None,
        http_method: str | None,
    ) -> AuthenticationResult:
        """Validate access token and optionally DPoP proof.

        Args:
            token: The access token to validate.
            jwks: The JWKS for signature verification.
            dpop: The DPoP proof JWT, or None if not using DPoP.
            path: The request path for DPoP validation.
            http_method: The HTTP method for DPoP validation.

        Returns:
            AuthenticationResult indicating success or failure.
        """
        jwt = SignedJwt(token)

        # Access token validation
        access_token_result = self._validate_access_token(jwt, jwks)
        if not access_token_result.success:
            return access_token_result

        # DPoP validation
        if dpop is not None:
            if path is None or http_method is None:
                return AuthenticationResult(
                    success=False, error="path and http_method are required for DPoP validation"
                )
            dpop_result = self._validate_dpop(dpop, path, http_method, token)
            if not dpop_result.success:
                return dpop_result

        return AuthenticationResult(success=True, payload=access_token_result.payload)

    def _should_retry_with_fresh_jwks(self, result: AuthenticationResult) -> bool:
        """Check if validation should be retried with fresh JWKS.

        Args:
            result: The authentication result from the first validation attempt.

        Returns:
            True if the cache should be invalidated and validation retried.
        """
        if result.success:
            return False

        if result.error == ERROR_JWK_NOT_FOUND:
            logger.debug("JWK key not found, invalidating cache and retrying")
            self._invalidate_cache()
            return True

        return False

    async def validate_async(
        self,
        token: str,
        dpop: str | None,
        path: str | None = None,
        http_method: str | None = None,
    ) -> AuthenticationResult:
        """Asynchronous validation: validate the access token and then the DPoP.

        If validation fails due to a missing JWK key, the cache is invalidated
        and a fresh JWKS is fetched before retrying once.
        """
        logger.debug("get jwks & jwt")
        jwks, _ = await self._get_jwks_async()
        logger.debug("token validation start")
        result = self._validate_token_and_dpop(token, jwks, dpop, path, http_method)

        if self._should_retry_with_fresh_jwks(result):
            jwks, _ = await self._get_jwks_async()
            result = self._validate_token_and_dpop(token, jwks, dpop, path, http_method)

        return result

    def validate(
        self,
        token: str,
        dpop: str | None,
        path: str | None = None,
        http_method: str | None = None,
    ) -> AuthenticationResult:
        """Synchronous validation: validate the access token and then the DPoP.

        If validation fails due to a missing JWK key, the cache is invalidated
        and a fresh JWKS is fetched before retrying once.
        """
        jwks, _ = self._get_jwks()
        result = self._validate_token_and_dpop(token, jwks, dpop, path, http_method)

        if self._should_retry_with_fresh_jwks(result):
            jwks, _ = self._get_jwks()
            result = self._validate_token_and_dpop(token, jwks, dpop, path, http_method)

        return result

    def get_scopes(self) -> list[str]:
        """Get the list of required scopes.

        Returns:
            List of scope strings required for authentication.
        """
        return self.scopes
