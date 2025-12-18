"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables first
load_dotenv()

from app.auth.adapter.input.web.router import router as auth_router
from app.account.infrastructure.orm.account_model import AccountModel  # noqa: F401
from config.database.session import Base, engine
from config.settings import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler.

    Startup: Initialize database tables.
    Shutdown: Cleanup resources if needed.
    """
    # Startup
    Base.metadata.create_all(bind=engine)
    yield
    # Shutdown (cleanup if needed)


app = FastAPI(
    title="Gugudan AI Server",
    description="AI Counselor for emotional problems between couples",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.CORS_ALLOWED_FRONTEND_URL],
    allow_credentials=True,  # Required for cookies
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(auth_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=settings.APP_HOST,
        port=settings.APP_PORT,
    )
