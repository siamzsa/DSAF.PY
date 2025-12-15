from __future__ import annotations
import datetime
import os
import secrets
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv
from fastapi import (
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

#
# Professional, lightweight license server for browser extensions.
# Features:
# - Token verification endpoint for extensions
# - Admin dashboard (session-protected) to create/toggle/delete licenses
# - SQLite storage (file-based) for portability
# - Minimal surface area and CORS enabled for extension calls
#


load_dotenv()

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
DATABASE_URL = f"sqlite:///{(DATA_DIR / 'licenses.db').as_posix()}"

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_hex(32))

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class License(Base):
    __tablename__ = "licenses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(120), index=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- Pydantic Schemas ----------
class LicenseCreate(BaseModel):
    username: str = Field(..., description="Username for this license")
    token: Optional[str] = Field(None, description="Custom token; if omitted, auto-generated")
    active: bool = True


class LicensePublic(BaseModel):
    id: int
    username: str
    token: str
    active: bool
    created_at: datetime.datetime

    class Config:
        orm_mode = True


class VerifyResponse(BaseModel):
    status: str
    valid: bool
    reason: Optional[str] = None


app = FastAPI(title="License Server", version="1.1.0")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, https_only=False)


# ---------- Utility ----------
def generate_token() -> str:
    # 32 bytes -> 64 hex characters
    return secrets.token_hex(32)


def validate_license(license: License) -> tuple[bool, Optional[str]]:
    if not license.active:
        return False, "inactive"
    if license.expires_at and license.expires_at < datetime.datetime.utcnow():
        return False, "expired"
    return True, None


def require_admin(request: Request) -> None:
    if not request.session.get("admin_auth"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


def ensure_admin_session(request: Request) -> Optional[RedirectResponse]:
    if not request.session.get("admin_auth"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return None


# ---------- API Endpoints ----------
@app.post("/verify-token", response_model=VerifyResponse)
def verify_token(payload: dict, db: Session = Depends(get_db)):
    token = payload.get("token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="token is required"
        )

    lic: Optional[License] = db.query(License).filter(License.token == token).first()
    if not lic:
        return VerifyResponse(status="error", valid=False, reason="not_found")

    ok, reason = validate_license(lic)
    if ok:
        return VerifyResponse(status="success", valid=True)
    return VerifyResponse(status="error", valid=False, reason=reason)


@app.get("/licenses", response_model=List[LicensePublic], dependencies=[Depends(require_admin)])
def list_licenses(db: Session = Depends(get_db)):
    return db.query(License).order_by(License.created_at.desc()).all()


@app.post("/licenses", response_model=LicensePublic, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
def create_license(payload: LicenseCreate, db: Session = Depends(get_db)):
    token = payload.token or generate_token()

    exists = db.query(License).filter(License.token == token).first()
    if exists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="token already exists"
        )

    lic = License(
        token=token,
        username=payload.username,
        active=payload.active,
        expires_at=None,
    )
    db.add(lic)
    db.commit()
    db.refresh(lic)
    return lic


@app.patch("/licenses/{license_id}", response_model=LicensePublic, dependencies=[Depends(require_admin)])
def update_license(
    license_id: int,
    payload: LicenseCreate,
    db: Session = Depends(get_db),
):
    lic: Optional[License] = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    for field, value in payload.dict(exclude_unset=True).items():
        if value is not None or field == "active":
            setattr(lic, field, value)

    db.commit()
    db.refresh(lic)
    return lic


@app.delete("/licenses/{license_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin)])
def delete_license(license_id: int, db: Session = Depends(get_db)):
    lic: Optional[License] = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    db.delete(lic)
    db.commit()
    return {}


# ---------- Auth & Admin UI ----------
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        request.session["admin_auth"] = True
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Incorrect password"},
        status_code=status.HTTP_401_UNAUTHORIZED,
    )


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    redirect = ensure_admin_session(request)
    if redirect:
        return redirect

    licenses = db.query(License).order_by(License.created_at.desc()).all()
    stats = {
        "total": len(licenses),
        "active": len([l for l in licenses if l.active]),
        "inactive": len([l for l in licenses if not l.active]),
        "expired": 0,
    }
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "licenses": licenses,
            "now": datetime.datetime.utcnow(),
            "stats": stats,
        },
    )


@app.post("/admin/licenses/create")
def admin_create_license(
    request: Request,
    username: str = Form(...),
    license_key: str = Form(...),
    active: bool = Form(True),
    db: Session = Depends(get_db),
):
    redirect = ensure_admin_session(request)
    if redirect:
        return redirect

    payload = LicenseCreate(
        username=username,
        token=license_key or None,
        active=active,
    )
    create_license(payload, db=db)  # reuse API logic
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/licenses/{license_id}/toggle")
def admin_toggle_license(license_id: int, request: Request, db: Session = Depends(get_db)):
    redirect = ensure_admin_session(request)
    if redirect:
        return redirect

    lic: Optional[License] = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    lic.active = not lic.active
    db.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/licenses/{license_id}/delete")
def admin_delete_license(license_id: int, request: Request, db: Session = Depends(get_db)):
    redirect = ensure_admin_session(request)
    if redirect:
        return redirect

    delete_license(license_id, db=db)
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)


