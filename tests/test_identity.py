from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from pydantic import ValidationError

from turnstile.identity import (
    IdentityError,
    RoleMapping,
    StaticPrincipalResolver,
    TokenPrincipalResolver,
    TokenSettings,
)

# At least 32 bytes: RFC 7518 section 3.2 sets that as the minimum for HS256,
# and PyJWT warns below it. A test that trips a security warning teaches the
# wrong lesson to anyone who copies it.
SECRET = "test-signing-secret-at-least-32-bytes-long"
WRONG_SECRET = "a-completely-different-secret-also-32-bytes"
ISSUER = "https://login.example.com/acme"
AUDIENCE = "turnstile"

MAPPING = RoleMapping(
    base_scopes=("read",),
    groups={
        "support-leads": ("tickets",),
        "finance": ("ledger",),
        "directors": ("ledger", "approve", "write"),
    },
)


def settings(**overrides: Any) -> TokenSettings:
    base: dict[str, Any] = {"algorithms": ("HS256",), "issuer": ISSUER, "audience": AUDIENCE}
    base.update(overrides)
    return TokenSettings(**base)


def token(
    *,
    subject: str = "priya",
    tenant: str = "acme",
    groups: Any = ("support-leads",),
    expires_in: int = 600,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    key: str = SECRET,
    algorithm: str = "HS256",
    omit: tuple[str, ...] = (),
) -> str:
    claims: dict[str, Any] = {
        "sub": subject,
        "tid": tenant,
        "groups": list(groups) if isinstance(groups, tuple) else groups,
        "iss": issuer,
        "aud": audience,
        "exp": int(time.time()) + expires_in,
        "iat": int(time.time()),
    }
    for field in omit:
        claims.pop(field, None)
    return jwt.encode(claims, key, algorithm=algorithm)


def resolver(**overrides: Any) -> TokenPrincipalResolver:
    return TokenPrincipalResolver(key=SECRET, settings=settings(**overrides), mapping=MAPPING)


class TestSignatureIsAlwaysVerified:
    """The checks whose absence turns a token into an unverified suggestion."""

    def test_valid_token_resolves(self) -> None:
        principal = resolver().resolve(token())
        assert principal.subject == "priya"
        assert principal.tenant == "acme"

    def test_token_signed_with_the_wrong_key_is_rejected(self) -> None:
        with pytest.raises(IdentityError, match="rejected"):
            resolver().resolve(token(key=WRONG_SECRET))

    def test_tampering_with_the_payload_is_rejected(self) -> None:
        # Forge a director claim onto a support token by swapping the payload.
        good = token(groups=("support-leads",))
        forged_payload = jwt.encode(
            {"sub": "priya", "tid": "acme", "groups": ["directors"], "iss": ISSUER,
             "aud": AUDIENCE, "exp": int(time.time()) + 600},
            WRONG_SECRET,
            algorithm="HS256",
        )
        header, _, _ = good.split(".")
        _, payload, signature = forged_payload.split(".")
        spliced = f"{header}.{payload}.{signature}"
        with pytest.raises(IdentityError):
            resolver().resolve(spliced)

    def test_alg_none_cannot_even_be_configured(self) -> None:
        # Signature stripping is not an algorithm choice.
        with pytest.raises(ValidationError, match="unsigned tokens are never acceptable"):
            TokenSettings(algorithms=("none",), issuer=ISSUER, audience=AUDIENCE)

    def test_expired_token_is_rejected(self) -> None:
        with pytest.raises(IdentityError):
            resolver().resolve(token(expires_in=-60))

    def test_token_without_an_expiry_is_rejected(self) -> None:
        # A token that never expires is a permanent credential.
        with pytest.raises(IdentityError):
            resolver().resolve(token(omit=("exp",)))

    def test_wrong_audience_is_rejected(self) -> None:
        # A token minted for a different service must not be replayable here.
        with pytest.raises(IdentityError):
            resolver().resolve(token(audience="some-other-service"))

    def test_wrong_issuer_is_rejected(self) -> None:
        with pytest.raises(IdentityError):
            resolver().resolve(token(issuer="https://attacker.example.com/"))

    def test_missing_credential_is_rejected(self) -> None:
        with pytest.raises(IdentityError, match="no credential"):
            resolver().resolve(None)

    def test_garbage_is_rejected(self) -> None:
        with pytest.raises(IdentityError):
            resolver().resolve("not-a-token")

    def test_error_never_echoes_the_token(self) -> None:
        # A credential in an error message ends up in logs, tickets and chats.
        secret_token = token(key=WRONG_SECRET)
        try:
            resolver().resolve(secret_token)
        except IdentityError as exc:
            assert secret_token not in str(exc)
        else:  # pragma: no cover
            pytest.fail("expected rejection")


class TestRoleMapping:
    def test_groups_confer_their_scopes(self) -> None:
        principal = resolver().resolve(token(groups=("finance",)))
        assert set(principal.scopes) == {"read", "ledger"}

    def test_multiple_groups_union_their_scopes(self) -> None:
        principal = resolver().resolve(token(groups=("finance", "support-leads")))
        assert set(principal.scopes) == {"read", "ledger", "tickets"}

    def test_an_unmapped_group_grants_nothing(self) -> None:
        # Default deny, applied to identity: creating a group at the IdP must
        # never be accidentally a grant inside Turnstile.
        principal = resolver().resolve(token(groups=("brand-new-group",)))
        assert set(principal.scopes) == {"read"}

    def test_base_scopes_apply_with_no_groups(self) -> None:
        assert set(resolver().resolve(token(groups=())).scopes) == {"read"}

    def test_a_single_string_groups_claim_is_read_correctly(self) -> None:
        # Providers differ: some emit a bare string when there is one group.
        # Treating that as absent would strip the caller's only group.
        principal = resolver().resolve(token(groups="directors"))
        assert "approve" in principal.scopes

    def test_non_string_entries_in_groups_are_ignored(self) -> None:
        principal = resolver().resolve(token(groups=["finance", 42, None]))
        assert set(principal.scopes) == {"read", "ledger"}

    def test_scopes_are_sorted_so_principals_compare_stably(self) -> None:
        principal = resolver().resolve(token(groups=("directors",)))
        assert list(principal.scopes) == sorted(principal.scopes)

    def test_explain_refuses_an_unverified_token(self) -> None:
        # explain() must not become a way to read claims out of a token nobody
        # verified. There is exactly one decode in the module and it verifies.
        with pytest.raises(IdentityError):
            resolver().explain(token(key=WRONG_SECRET))
        with pytest.raises(IdentityError):
            resolver().explain(token(expires_in=-60))

    def test_explain_surfaces_groups_the_mapping_ignores(self) -> None:
        # The commonest identity failure is an accepted token with fewer scopes
        # than expected, which looks exactly like a policy bug.
        report = resolver().explain(token(groups=("finance", "mystery-group")))
        assert report["groups_unmapped"] == ["mystery-group"]
        assert "ledger" in report["scopes_granted"]


class TestClaims:
    def test_missing_subject_claim_is_rejected(self) -> None:
        with pytest.raises(IdentityError, match="sub"):
            resolver().resolve(token(omit=("sub",)))

    def test_missing_tenant_claim_is_rejected(self) -> None:
        # Without a tenant there is no isolation boundary to enforce.
        with pytest.raises(IdentityError, match="tid"):
            resolver().resolve(token(omit=("tid",)))

    def test_tenant_claim_name_is_configurable(self) -> None:
        custom = TokenPrincipalResolver(
            key=SECRET, settings=settings(tenant_claim="org_id"), mapping=MAPPING
        )
        payload = jwt.encode(
            {"sub": "p", "org_id": "globex", "groups": ["finance"], "iss": ISSUER,
             "aud": AUDIENCE, "exp": int(time.time()) + 600},
            SECRET,
            algorithm="HS256",
        )
        assert custom.resolve(payload).tenant == "globex"


class TestStaticResolver:
    def test_returns_the_configured_principal(self) -> None:
        from turnstile.domain import Principal

        fixed = Principal(tenant="acme", subject="local-user", scopes=("read",))
        assert StaticPrincipalResolver(fixed).resolve(None) == fixed


class TestTwoUsersSamePolicy:
    """The demo: the same question, two people, different answers."""

    @staticmethod
    def policy() -> Any:
        from turnstile.domain import Effect
        from turnstile.policy import Policy, Rule

        return Policy(
            rules=(
                Rule(id="approve-needs-director", effect=Effect.ALLOW, tools=("approve_payment",),
                     require_scopes=("approve",)),
                Rule(id="ledger-needs-finance", effect=Effect.ALLOW, tools=("query_ledger",),
                     require_scopes=("ledger",)),
                Rule(id="reads-for-everyone", effect=Effect.ALLOW, tools=("read_*",)),
            )
        )

    def call_as(self, principal: Any, tool: str) -> Any:
        from turnstile.domain import ToolCall

        return self.policy().evaluate(ToolCall(server="fin", tool=tool, principal=principal))

    def test_support_lead_cannot_query_the_ledger(self) -> None:
        priya = resolver().resolve(token(subject="priya", groups=("support-leads",)))
        assert not self.call_as(priya, "query_ledger").is_allowed

    def test_finance_can_query_the_ledger_but_not_approve(self) -> None:
        sam = resolver().resolve(token(subject="sam", groups=("finance",)))
        assert self.call_as(sam, "query_ledger").is_allowed
        assert not self.call_as(sam, "approve_payment").is_allowed

    def test_director_can_do_both(self) -> None:
        dana = resolver().resolve(token(subject="dana", groups=("directors",)))
        assert self.call_as(dana, "query_ledger").is_allowed
        assert self.call_as(dana, "approve_payment").is_allowed

    def test_everyone_can_read(self) -> None:
        for groups in (("support-leads",), ("finance",), ("directors",)):
            who = resolver().resolve(token(groups=groups))
            assert self.call_as(who, "read_note").is_allowed
