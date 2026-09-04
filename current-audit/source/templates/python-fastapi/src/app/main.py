from fastapi import FastAPI
app=FastAPI(title="__PROJECT_NAME__")
@app.get("/healthz")
def healthz() -> dict[str,bool]: return {"ok":True}
