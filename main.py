"""Local entry point. Production should invoke uvicorn directly."""
import os

import uvicorn

from app.logsafe import uvicorn_log_config

if __name__ == "__main__":
    uvicorn.run("app.app:app", host=os.getenv("HOST", "127.0.0.1"),
                port=int(os.getenv("PORT", "8080")), reload=False,
                access_log=False, proxy_headers=False,
                # Never let the server log a traceback: exception strings can
                # contain staging paths. Only the exception class name is kept.
                log_config=uvicorn_log_config(os.getenv("LOG_LEVEL", "INFO").upper()))
