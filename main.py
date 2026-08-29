"""Local entry point. Production should invoke uvicorn directly."""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.app:app", host=os.getenv("HOST", "127.0.0.1"),
                port=int(os.getenv("PORT", "8080")), reload=False,
                access_log=False, proxy_headers=False)
