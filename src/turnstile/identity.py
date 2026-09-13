"""Turning a corporate identity into a principal the policy engine can judge.

The point of this module is a single sentence: **an agent must never hold more
authority than the person it acts for, and usually holds less.**

Role-based access control answers the first half. Every company already has an
identity provider that knows Priya is in `support-leads`, and re-implementing
that would be pointless. So Turnstile consumes what the IdP already asserts --
it authenticates nobody itself -- and maps the groups in a signed token onto
the scopes its rules select on.

The second half, "usually less", is what policy is for and lives elsewhere.
Priya may legitimately delete a row; an agent acting as Priya, in a loop, at
3am, prompted by a document it just read, is a different act with the same
permission. This module decides the ceiling. The rules decide what happens
below it.

Two properties are enforced here rather than left to configuration:

* **The signature is always verified.** There is no flag that turns it off.
* **An unmapped group grants nothing.** A group the operator has not written a
  mapping for contributes no scopes, so adding a group at the IdP never
  silently widens what agents may do.
"""

from __future__ import annotations

from typing import Any, Protocol

import jwt
from pydantic import BaseModel, ConfigDict, Field

from .domain import Principal

FORBIDDEN_ALGORITHMS = frozenset({"none", "None", "NONE"})
"""`alg: none` is a signature-stripping attack, not an algorithm. Rejected explicitly
so a misconfiguration cannot reintroduce it."""


class IdentityError(Exception):
    """The caller's identity could not be established. Never carries token contents."""


class RoleMapping(BaseModel):
    """IdP group -> scopes.

    Written by an operator, reviewed in a pull request. A group with no entry
    here grants nothing: default-deny applied to identity, so that creating a
    group at the IdP is never accidentally a grant inside Turnstile.
    """

    model_config = ConfigDict(frozen=True)

    groups: dict[str, tuple[str, ...]] = Field(
        default_factory=dict,
        description="Group name -> the scopes it confers.",
    )
    base_scopes: tuple[str, ...] = Field(
        default=(),
        description="Scopes every authenticated caller gets, whatever their groups.",
    )

    def scopes_for(self, groups: list[str]) -> tuple[str, ...]:
        resolved = set(self.base_scopes)
        for group in groups:
            resolved.update(self.groups.get(group, ()))
        return tuple(sorted(resolved))

    def unmapped(self, groups: list[str]) -> tuple[str, ...]:
        """Groups the caller holds that this mapping says nothing about.

        Surfaced rather than swallowed: silently ignoring a group is how an
        operator concludes their mapping works when it does not.
        """
        return tuple(sorted(group for group in groups if group not in self.groups))


class PrincipalResolver(Protocol):
    """How a request becomes a principal."""

    def resolve(self, credential: str | None) -> Principal: ...


class StaticPrincipalResolver:
    """A principal fixed in configuration.

    Honest for a single-user stdio deployment, where the client launches the
    gateway as one person and the transport carries no authorization. It is not
    multi-user and does not pretend to be: whoever runs the process is whoever
    the config says.
    """

    def __init__(self, principal: Principal) -> None:
        self._principal = principal

    def resolve(self, credential: str | None) -> Principal:
        return self._principal


class TokenSettings(BaseModel):
    """How to validate an OIDC token and read a principal out of it."""

    model_config = ConfigDict(frozen=True)

    algorithms: tuple[str, ...] = ("RS256",)
    issuer: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    subject_claim: str = "sub"
    tenant_claim: str = Field(default="tid", description="Entra ID uses 'tid'; Okta commonly uses a custom claim.")
    groups_claim: str = "groups"
    leeway_seconds: int = Field(default=0, ge=0, le=300)

    def model_post_init(self, _context: object, /) -> None:
        forbidden = FORBIDDEN_ALGORITHMS.intersection(self.algorithms)
        if forbidden:
            raise ValueError(f"unsigned tokens are never acceptable; remove {sorted(forbidden)} from algorithms")


class TokenPrincipalResolver:
    """Validates a signed token and maps its groups onto scopes.

    `key` is the verification key -- a public key for RS256, a shared secret for
    HS256 (useful for a local demo, unsuitable for real deployment because
    anyone who can verify can also mint).
    """

    def __init__(self, *, key: str, settings: TokenSettings, mapping: RoleMapping) -> None:
        self._key = key
        self._settings = settings
        self._mapping = mapping

    def resolve(self, credential: str | None) -> Principal:
        if not credential:
            raise IdentityError("no credential presented")

        try:
            claims: dict[str, Any] = jwt.decode(
                credential,
                self._key,
                algorithms=list(self._settings.algorithms),
                audience=self._settings.audience,
                issuer=self._settings.issuer,
                leeway=self._settings.leeway_seconds,
                options={
                    # Named explicitly rather than relying on library defaults:
                    # these are the checks whose absence turns a token into a
                    # suggestion, and a future default change must not silently
                    # disable one.
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require": ["exp", "iss", "aud"],
                },
            )
        except jwt.InvalidTokenError as exc:
            # The reason is reported; the token is not. Echoing a credential
            # into a log or an error message is how it ends up somewhere it
            # should never have been.
            raise IdentityError(f"token rejected: {type(exc).__name__}: {exc}") from exc

        subject = claims.get(self._settings.subject_claim)
        if not isinstance(subject, str) or not subject:
            raise IdentityError(f"token has no usable {self._settings.subject_claim!r} claim")

        tenant = claims.get(self._settings.tenant_claim)
        if not isinstance(tenant, str) or not tenant:
            raise IdentityError(f"token has no usable {self._settings.tenant_claim!r} claim")

        groups = _string_list(claims.get(self._settings.groups_claim))
        scopes = self._mapping.scopes_for(groups)

        return Principal(tenant=tenant, subject=subject, scopes=scopes)

    def explain(self, credential: str | None) -> dict[str, Any]:
        """Diagnostics for `turnstile whoami`: what was read, and what was ignored.

        Exists because the commonest identity failure is not a rejected token
        but an accepted one that produced fewer scopes than expected, which
        looks exactly like a policy bug until someone can see the mapping.
        """
        principal = self.resolve(credential)
        claims = jwt.decode(credential or "", options={"verify_signature": False})
        groups = _string_list(claims.get(self._settings.groups_claim))
        return {
            "principal": principal.model_dump(),
            "groups_presented": groups,
            "groups_unmapped": list(self._mapping.unmapped(groups)),
            "scopes_granted": list(principal.scopes),
        }


def _string_list(value: Any) -> list[str]:
    """Read a groups claim that may be a list, a single string, or absent.

    Providers genuinely differ: some emit an array, some a single string when
    there is one group. Treating the string case as absent would quietly strip
    a caller's only group.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []
