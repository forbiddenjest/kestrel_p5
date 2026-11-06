"""Standalone process entry point for background jobs and metrics."""
import asyncio
from app.worker import worker_loop

if __name__ == "__main__":
    asyncio.run(worker_loop())
