"""OAuth providers response schema."""

from pydantic import BaseModel


class OAuthProvidersResponse(BaseModel):
    """Response listing supported OAuth providers."""

    providers: list[str]
