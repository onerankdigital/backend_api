"""
Product Service - Industry → Category → Product hierarchy
"""
from fastapi import FastAPI, Depends, HTTPException, status as http_status, UploadFile, File, Form, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, text
from sqlalchemy.exc import SQLAlchemyError, OperationalError, ProgrammingError
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import sys
import os
import shutil
from pathlib import Path
import logging
import traceback

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db, Base
from shared.models.base import BaseModel as BaseDBModel
from sqlalchemy import Column, String, ForeignKey, DateTime, Boolean, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Product Service", version="1.0.0")

# Startup event - verify database connection
@app.on_event("startup")
async def startup_event():
    """Verify database connection and table existence on startup"""
    try:
        async for db in get_db():
            try:
                # Check if industries table exists and has required columns
                result = await db.execute(text("""
                    SELECT column_name, data_type 
                    FROM information_schema.columns 
                    WHERE table_name = 'industries'
                """))
                columns = {row[0]: row[1] for row in result.fetchall()}
                
                if not columns:
                    logger.warning("Industries table does not exist. Please run database migrations.")
                else:
                    logger.info(f"Industries table found with columns: {list(columns.keys())}")
                    # Check for required columns
                    required_columns = ['id', 'name', 'status', 'is_home', 'is_top']
                    missing_columns = [col for col in required_columns if col not in columns]
                    if missing_columns:
                        logger.warning(f"Industries table missing columns: {missing_columns}. Please run database migrations.")
                    else:
                        logger.info("All required columns present in industries table")
                
                # Test a simple query
                await db.execute(text("SELECT 1"))
                logger.info("Database connection verified successfully")
            finally:
                await db.close()
            break
    except Exception as e:
        logger.error(f"Database connection check failed: {e}", exc_info=True)
        logger.error("Please ensure database is running and migrations are applied")

# Exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors"""
    # Filter out UploadFile objects from errors to prevent serialization issues
    errors = exc.errors()
    filtered_errors = []
    for error in errors:
        filtered_error = error.copy()
        # Replace UploadFile objects in 'input' field with a string representation
        if 'input' in filtered_error:
            input_val = filtered_error['input']
            if hasattr(input_val, 'read'):  # It's an UploadFile
                filtered_error['input'] = f"<UploadFile: {getattr(input_val, 'filename', 'file')}>"
        filtered_errors.append(filtered_error)
    
    logger.error(f"Validation error in {request.url.path}: {filtered_errors}")
    return JSONResponse(
        status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "error": "Request validation failed",
            "errors": filtered_errors
        }
    )

@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    """Handle SQLAlchemy database errors"""
    logger.error(f"Database error in {request.url.path}: {exc}", exc_info=True)
    error_msg = str(exc)
    
    # Provide more specific error messages
    if isinstance(exc, OperationalError):
        error_msg = f"Database connection error: {error_msg}"
    elif isinstance(exc, ProgrammingError):
        error_msg = f"Database query error: {error_msg}"
    
    return JSONResponse(
        status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Database error occurred",
            "error": error_msg
        }
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors"""
    logger.error(f"Unhandled exception in {request.url.path}: {exc}", exc_info=True)
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    return JSONResponse(
        status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error": str(exc),
            "type": type(exc).__name__
        }
    )

# Create upload directory
# In Docker, files are at /app/uploads/images (volume mounted from ./uploads)
# In local dev, files are at backend_api/uploads/images
UPLOAD_DIR = Path("/app/uploads/images") if Path("/app/uploads").exists() else Path(__file__).parent.parent.parent / "uploads" / "images"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Mount static files for serving images
app.mount("/static/images", StaticFiles(directory=str(UPLOAD_DIR)), name="images")


def save_uploaded_file(file: UploadFile, subfolder: str = "") -> str:
    """Save uploaded file and return relative path"""
    # Create subfolder if specified
    target_dir = UPLOAD_DIR / subfolder
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate unique filename
    file_ext = Path(file.filename).suffix
    filename = f"{uuid.uuid4()}{file_ext}"
    file_path = target_dir / filename
    
    # Save file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # Return relative path for storage in database
    relative_path = f"/static/images/{subfolder}/{filename}" if subfolder else f"/static/images/{filename}"
    return relative_path


# Database Models
class Industry(BaseDBModel):
    __tablename__ = "industries"
    
    name = Column(String, unique=True, nullable=False, index=True)
    description = Column(String, nullable=True)
    status = Column(String, default="active", nullable=False)
    is_home = Column(Boolean, default=False, nullable=False)
    is_top = Column(Boolean, default=False, nullable=False)
    image = Column(String, nullable=True)
    logo = Column(String, nullable=True)


class ProductCategory(BaseDBModel):
    __tablename__ = "product_categories"
    
    industry_id = Column(UUID(as_uuid=True), ForeignKey("industries.id"), nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    status = Column(String, default="active", nullable=False)
    image = Column(String, nullable=True)


class Product(BaseDBModel):
    __tablename__ = "products"
    
    category_id = Column(UUID(as_uuid=True), ForeignKey("product_categories.id"), nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    status = Column(String, default="active", nullable=False)


class ClientProduct(Base):
    """Client-Product junction table with composite primary key - no id, created_at, or updated_at columns
    
    Note: Foreign key to clients.client_id exists at DB level but clients table is not defined
    in this service (it's in client_service). The FK constraint is managed by the database.
    """
    __tablename__ = "client_products"
    __abstract__ = False
    
    # String FK reference - clients table managed by client_service, FK exists at DB level
    client_id = Column(String, nullable=False, primary_key=True, index=True)
    product_id = Column(UUID(as_uuid=True), ForeignKey("products.id"), nullable=False, primary_key=True, index=True)
    enabled = Column(String, default="true", nullable=False)  # Boolean as string
    attached_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ProductImage(BaseDBModel):
    __tablename__ = "product_images"
    
    product_id = Column(UUID(as_uuid=True), ForeignKey("products.id", ondelete="CASCADE"), nullable=False, index=True)
    image_url = Column(String, nullable=False)
    display_order = Column(Integer, default=0, nullable=False)


# Pydantic Schemas
class IndustryCreate(BaseModel):
    name: str
    description: Optional[str] = None
    status: str = "active"
    is_home: bool = False
    is_top: bool = False
    image: Optional[str] = None


class IndustryResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    status: str
    is_home: bool
    is_top: bool
    image: Optional[str] = None
    logo: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ProductCategoryCreate(BaseModel):
    industry_id: str
    name: str
    description: Optional[str] = None
    status: str = "active"
    image: Optional[str] = None


class ProductCategoryResponse(BaseModel):
    id: str
    industry_id: str
    industry_name: Optional[str] = None
    name: str
    description: Optional[str]
    status: str
    image: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ProductCreate(BaseModel):
    category_id: str
    name: str
    description: Optional[str] = None
    status: str = "active"


class ProductResponse(BaseModel):
    id: str
    category_id: str
    category_name: Optional[str] = None
    name: str
    description: Optional[str]
    status: str
    first_image: Optional[str] = None  # URL of the first product image
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ClientProductAttach(BaseModel):
    client_id: str
    product_id: str
    enabled: bool = True


class ClientProductResponse(BaseModel):
    client_id: str
    product_id: str
    product_name: Optional[str] = None
    enabled: bool
    attached_at: datetime


class ProductImageCreate(BaseModel):
    product_id: str
    image_url: str
    display_order: int = 0


class ProductImageUpdate(BaseModel):
    image_url: Optional[str] = None
    display_order: Optional[int] = None


class ProductImageResponse(BaseModel):
    id: str
    product_id: str
    product_name: Optional[str] = None
    image_url: str
    display_order: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# Routes - Industries
@app.post("/industries", response_model=IndustryResponse, status_code=http_status.HTTP_201_CREATED)
async def create_industry(
    name: str = Form(...),
    description: Optional[str] = Form(None),
    industry_status: str = Form("active", alias="status"),
    is_home: bool = Form(False),
    is_top: bool = Form(False),
    image: Optional[UploadFile] = File(None),
    logo: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db)
):
    """Create a new industry"""
    try:
        # Check uniqueness
        result = await db.execute(select(Industry).where(Industry.name == name))
        existing = result.scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail=f"Industry '{name}' already exists"
            )
        
        # Save image if provided
        image_path = None
        if image:
            try:
                image_path = save_uploaded_file(image, "industries")
            except Exception as e:
                logger.error(f"Error saving image: {e}")
                raise HTTPException(
                    status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to save image: {str(e)}"
                )
        
        # Save logo if provided
        logo_path = None
        if logo:
            try:
                logo_path = save_uploaded_file(logo, "industries/logos")
            except Exception as e:
                logger.error(f"Error saving logo: {e}")
                raise HTTPException(
                    status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to save logo: {str(e)}"
                )
        
        new_industry = Industry(
            name=name,
            description=description,
            status=industry_status,
            is_home=is_home,
            is_top=is_top,
            image=image_path,
            logo=logo_path
        )
        
        db.add(new_industry)
        try:
            await db.commit()
            await db.refresh(new_industry)
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Database error creating industry: {e}")
            raise HTTPException(
                status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )
        
        return IndustryResponse(
            id=str(new_industry.id),
            name=new_industry.name,
            description=new_industry.description,
            status=new_industry.status,
            is_home=new_industry.is_home,
            is_top=new_industry.is_top,
            image=new_industry.image,
            logo=new_industry.logo,
            created_at=new_industry.created_at,
            updated_at=new_industry.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating industry: {e}", exc_info=True)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create industry: {str(e)}"
        )


@app.get("/industries", response_model=List[IndustryResponse])
async def list_industries(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all industries"""
    query = select(Industry)
    if status_filter:
        query = query.where(Industry.status == status_filter)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    industries = result.scalars().all()
    
    return [
        IndustryResponse(
            id=str(ind.id),
            name=ind.name,
            description=ind.description,
            status=ind.status,
            is_home=ind.is_home,
            is_top=ind.is_top,
            image=ind.image,
            logo=ind.logo,
            created_at=ind.created_at,
            updated_at=ind.updated_at
        )
        for ind in industries
    ]


@app.get("/industries/top", response_model=List[IndustryResponse])
async def get_top_industries(
    db: AsyncSession = Depends(get_db)
):
    """Get all industries where is_top is true"""
    query = select(Industry).where(
        and_(
            Industry.is_top == True,
            Industry.status == "active"
        )
    ).order_by(Industry.name)
    
    result = await db.execute(query)
    industries = result.scalars().all()
    
    return [
        IndustryResponse(
            id=str(ind.id),
            name=ind.name,
            description=ind.description,
            status=ind.status,
            is_home=ind.is_home,
            is_top=ind.is_top,
            image=ind.image,
            logo=ind.logo,
            created_at=ind.created_at,
            updated_at=ind.updated_at
        )
        for ind in industries
    ]


@app.get("/industries/home", response_model=List[IndustryResponse])
async def get_home_industries(
    db: AsyncSession = Depends(get_db)
):
    """Get all industries where is_home is true (for industry map display)"""
    query = select(Industry).where(
        and_(
            Industry.is_home == True,
            Industry.status == "active"
        )
    ).order_by(Industry.name)
    
    result = await db.execute(query)
    industries = result.scalars().all()
    
    return [
        IndustryResponse(
            id=str(ind.id),
            name=ind.name,
            description=ind.description,
            status=ind.status,
            is_home=ind.is_home,
            is_top=ind.is_top,
            image=ind.image,
            logo=ind.logo,
            created_at=ind.created_at,
            updated_at=ind.updated_at
        )
        for ind in industries
    ]


@app.get("/industries/{industry_id}", response_model=IndustryResponse)
async def get_industry(industry_id: str, db: AsyncSession = Depends(get_db)):
    """Get industry by ID"""
    result = await db.execute(select(Industry).where(Industry.id == uuid.UUID(industry_id)))
    industry = result.scalar_one_or_none()
    
    if not industry:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Industry {industry_id} not found"
        )
    
    return IndustryResponse(
        id=str(industry.id),
        name=industry.name,
        description=industry.description,
        status=industry.status,
        is_home=industry.is_home,
        is_top=industry.is_top,
        image=industry.image,
        logo=industry.logo,
        created_at=industry.created_at,
        updated_at=industry.updated_at
    )


@app.put("/industries/{industry_id}", response_model=IndustryResponse)
async def update_industry(
    industry_id: str,
    name: str = Form(None),
    description: Optional[str] = Form(None),
    industry_status: str = Form(None),
    is_home: Optional[bool] = Form(None),
    is_top: Optional[bool] = Form(None),
    image: Optional[UploadFile] = File(None),
    logo: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db)
):
    """Update an industry"""
    try:
        result = await db.execute(select(Industry).where(Industry.id == uuid.UUID(industry_id)))
        industry = result.scalar_one_or_none()
        
        if not industry:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Industry {industry_id} not found"
            )
        
        # Update fields if provided
        if name is not None:
            # Check uniqueness if name changed
            if name != industry.name:
                existing = await db.execute(select(Industry).where(Industry.name == name))
                if existing.scalar_one_or_none():
                    raise HTTPException(
                        status_code=http_status.HTTP_400_BAD_REQUEST,
                        detail=f"Industry '{name}' already exists"
                    )
            industry.name = name
        
        if description is not None:
            industry.description = description
        
        if industry_status is not None:
            industry.status = industry_status
        
        if is_home is not None:
            industry.is_home = is_home
        
        if is_top is not None:
            industry.is_top = is_top
        
        # Handle image update
        if image:
            try:
                image_path = save_uploaded_file(image, "industries")
                industry.image = image_path
            except Exception as e:
                logger.error(f"Error saving image: {e}")
                raise HTTPException(
                    status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to save image: {str(e)}"
                )
        
        # Handle logo update
        if logo:
            try:
                logo_path = save_uploaded_file(logo, "industries/logos")
                industry.logo = logo_path
            except Exception as e:
                logger.error(f"Error saving logo: {e}")
                raise HTTPException(
                    status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to save logo: {str(e)}"
                )
        
        try:
            await db.commit()
            await db.refresh(industry)
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Database error updating industry: {e}")
            raise HTTPException(
                status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )
        
        return IndustryResponse(
            id=str(industry.id),
            name=industry.name,
            description=industry.description,
            status=industry.status,
            is_home=industry.is_home,
            is_top=industry.is_top,
            image=industry.image,
            logo=industry.logo,
            created_at=industry.created_at,
            updated_at=industry.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error updating industry: {e}", exc_info=True)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update industry: {str(e)}"
        )


@app.delete("/industries/{industry_id}", status_code=http_status.HTTP_204_NO_CONTENT)
async def delete_industry(industry_id: str, db: AsyncSession = Depends(get_db)):
    """Delete an industry"""
    try:
        result = await db.execute(select(Industry).where(Industry.id == uuid.UUID(industry_id)))
        industry = result.scalar_one_or_none()
        
        if not industry:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Industry {industry_id} not found"
            )
        
        try:
            await db.delete(industry)
            await db.commit()
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Database error deleting industry: {e}")
            raise HTTPException(
                status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )
        
        return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error deleting industry: {e}", exc_info=True)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete industry: {str(e)}"
        )


# Routes - Product Categories
@app.post("/product-categories", response_model=ProductCategoryResponse, status_code=http_status.HTTP_201_CREATED)
async def create_product_category(
    industry_id: str = Form(...),
    name: str = Form(...),
    description: Optional[str] = Form(None),
    category_status: str = Form("active", alias="status"),
    image: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db)
):
    """Create a new product category"""
    # Validate industry exists
    result = await db.execute(
        select(Industry).where(Industry.id == uuid.UUID(industry_id))
    )
    industry = result.scalar_one_or_none()
    if not industry:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Industry {industry_id} not found"
        )
    
    # Save image if provided
    image_path = None
    if image:
        image_path = save_uploaded_file(image, "categories")
    
    new_category = ProductCategory(
        industry_id=uuid.UUID(industry_id),
        name=name,
        description=description,
        status=category_status,
        image=image_path
    )
    
    db.add(new_category)
    await db.commit()
    await db.refresh(new_category)
    
    return ProductCategoryResponse(
        id=str(new_category.id),
        industry_id=str(new_category.industry_id),
        industry_name=industry.name,
        name=new_category.name,
        description=new_category.description,
        status=new_category.status,
        image=new_category.image,
        created_at=new_category.created_at,
        updated_at=new_category.updated_at
    )


@app.get("/product-categories", response_model=List[ProductCategoryResponse])
async def list_product_categories(
    industry_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List product categories"""
    query = select(ProductCategory, Industry.name.label("industry_name")).join(
        Industry, ProductCategory.industry_id == Industry.id
    )
    
    if industry_id:
        query = query.where(ProductCategory.industry_id == uuid.UUID(industry_id))
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    rows = result.all()
    
    return [
        ProductCategoryResponse(
            id=str(row.ProductCategory.id),
            industry_id=str(row.ProductCategory.industry_id),
            industry_name=row.industry_name,
            name=row.ProductCategory.name,
            description=row.ProductCategory.description,
            status=row.ProductCategory.status,
            image=row.ProductCategory.image,
            created_at=row.ProductCategory.created_at,
            updated_at=row.ProductCategory.updated_at
        )
        for row in rows
    ]


@app.put("/product-categories/{category_id}", response_model=ProductCategoryResponse)
async def update_product_category(
    category_id: str,
    industry_id: Optional[str] = Form(None),
    name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    category_status: Optional[str] = Form(None, alias="status"),
    image: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db)
):
    """Update a product category"""
    result = await db.execute(
        select(ProductCategory, Industry.name.label("industry_name")).join(
            Industry, ProductCategory.industry_id == Industry.id
        ).where(ProductCategory.id == uuid.UUID(category_id))
    )
    row = result.first()
    
    if not row:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product category {category_id} not found"
        )
    
    category = row.ProductCategory
    
    # Update fields if provided
    if industry_id is not None:
        # Validate new industry exists
        industry_result = await db.execute(select(Industry).where(Industry.id == uuid.UUID(industry_id)))
        new_industry = industry_result.scalar_one_or_none()
        if not new_industry:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Industry {industry_id} not found"
            )
        category.industry_id = uuid.UUID(industry_id)
    
    if name is not None:
        category.name = name
    if description is not None:
        category.description = description
    if category_status is not None:
        category.status = category_status
    
    # Update image if provided
    if image:
        image_path = save_uploaded_file(image, "categories")
        category.image = image_path
    
    await db.commit()
    await db.refresh(category)
    
    # Get updated industry name
    result = await db.execute(select(Industry).where(Industry.id == category.industry_id))
    industry = result.scalar_one_or_none()
    
    return ProductCategoryResponse(
        id=str(category.id),
        industry_id=str(category.industry_id),
        industry_name=industry.name if industry else row.industry_name,
        name=category.name,
        description=category.description,
        status=category.status,
        image=category.image,
        created_at=category.created_at,
        updated_at=category.updated_at
    )


@app.delete("/product-categories/{category_id}")
async def delete_product_category(
    category_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Delete a product category"""
    result = await db.execute(
        select(ProductCategory).where(ProductCategory.id == uuid.UUID(category_id))
    )
    category = result.scalar_one_or_none()
    
    if not category:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product category {category_id} not found"
        )
    
    await db.delete(category)
    await db.commit()
    
    return {"message": "Product category deleted successfully"}


# Routes - Products
@app.post("/products", response_model=ProductResponse, status_code=http_status.HTTP_201_CREATED)
async def create_product(
    category_id: str = Form(...),
    name: str = Form(...),
    description: Optional[str] = Form(None),
    product_status: str = Form("active", alias="status"),
    images: List[UploadFile] = File([]),
    db: AsyncSession = Depends(get_db)
):
    """Create a new product with optional multiple images"""
    # Validate category exists
    result = await db.execute(
        select(ProductCategory).where(ProductCategory.id == uuid.UUID(category_id))
    )
    category = result.scalar_one_or_none()
    if not category:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product category {category_id} not found"
        )
    
    new_product = Product(
        category_id=uuid.UUID(category_id),
        name=name,
        description=description,
        status=product_status
    )
    
    db.add(new_product)
    await db.commit()
    await db.refresh(new_product)
    
    # Save product images if provided
    if images:
        for display_order, image_file in enumerate(images):
            if image_file.filename:  # Skip empty file uploads
                image_path = save_uploaded_file(image_file, "products")
                product_image = ProductImage(
                    product_id=new_product.id,
                    image_url=image_path,
                    display_order=display_order
                )
                db.add(product_image)
        await db.commit()
    
    # Get first image for this product
    image_result = await db.execute(
        select(ProductImage).where(ProductImage.product_id == new_product.id)
        .order_by(ProductImage.display_order, ProductImage.created_at)
        .limit(1)
    )
    first_image = image_result.scalar_one_or_none()
    
    return ProductResponse(
        id=str(new_product.id),
        category_id=str(new_product.category_id),
        category_name=category.name,
        name=new_product.name,
        description=new_product.description,
        status=new_product.status,
        first_image=first_image.image_url if first_image else None,
        created_at=new_product.created_at,
        updated_at=new_product.updated_at
    )


@app.get("/products", response_model=List[ProductResponse])
async def list_products(
    category_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List products"""
    query = select(Product, ProductCategory.name.label("category_name")).join(
        ProductCategory, Product.category_id == ProductCategory.id
    )
    
    if category_id:
        query = query.where(Product.category_id == uuid.UUID(category_id))
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    rows = result.all()
    
    # Build list with first images
    products_list = []
    for row in rows:
        # Get first image for this product (ordered by display_order, then created_at)
        image_result = await db.execute(
            select(ProductImage).where(ProductImage.product_id == row.Product.id)
            .order_by(ProductImage.display_order, ProductImage.created_at)
            .limit(1)
        )
        first_image = image_result.scalar_one_or_none()
        
        products_list.append(
            ProductResponse(
                id=str(row.Product.id),
                category_id=str(row.Product.category_id),
                category_name=row.category_name,
                name=row.Product.name,
                description=row.Product.description,
                status=row.Product.status,
                first_image=first_image.image_url if first_image else None,
                created_at=row.Product.created_at,
                updated_at=row.Product.updated_at
            )
        )
    
    return products_list


@app.get("/products/{product_id}", response_model=ProductResponse)
async def get_product(product_id: str, db: AsyncSession = Depends(get_db)):
    """Get product by ID"""
    result = await db.execute(
        select(Product, ProductCategory.name.label("category_name")).join(
            ProductCategory, Product.category_id == ProductCategory.id
        ).where(Product.id == uuid.UUID(product_id))
    )
    row = result.first()
    
    if not row:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product {product_id} not found"
        )
    
    # Get first image for this product
    image_result = await db.execute(
        select(ProductImage).where(ProductImage.product_id == row.Product.id)
        .order_by(ProductImage.display_order, ProductImage.created_at)
        .limit(1)
    )
    first_image = image_result.scalar_one_or_none()
    
    return ProductResponse(
        id=str(row.Product.id),
        category_id=str(row.Product.category_id),
        category_name=row.category_name,
        name=row.Product.name,
        description=row.Product.description,
        status=row.Product.status,
        first_image=first_image.image_url if first_image else None,
        created_at=row.Product.created_at,
        updated_at=row.Product.updated_at
    )


@app.put("/products/{product_id}", response_model=ProductResponse)
async def update_product(
    product_id: str,
    request: Request,
    category_id: Optional[str] = Form(None),
    name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    product_status: Optional[str] = Form(None, alias="status"),
    db: AsyncSession = Depends(get_db)
):
    """Update a product"""
    result = await db.execute(
        select(Product, ProductCategory.name.label("category_name")).join(
            ProductCategory, Product.category_id == ProductCategory.id
        ).where(Product.id == uuid.UUID(product_id))
    )
    row = result.first()
    
    if not row:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product {product_id} not found"
        )
    
    product = row.Product
    category_name = row.category_name
    
    # Update fields if provided
    if category_id is not None:
        # Validate new category exists
        category_result = await db.execute(
            select(ProductCategory).where(ProductCategory.id == uuid.UUID(category_id))
        )
        new_category = category_result.scalar_one_or_none()
        if not new_category:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Product category {category_id} not found"
            )
        product.category_id = uuid.UUID(category_id)
        category_name = new_category.name
    
    if name is not None:
        product.name = name
    if description is not None:
        product.description = description
    if product_status is not None:
        product.status = product_status
    
    # Handle multiple images manually from form (for forwarded requests from API gateway)
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" in content_type:
        form = await request.form()
        # Get all files with key "images" from form
        images_list = []
        # Access _list to get all entries including duplicates with same key
        if hasattr(form, '_list'):
            for entry in form._list:
                if isinstance(entry, (tuple, list)) and len(entry) >= 2:
                    key, value = entry[0], entry[1]
                    if key == "images" and hasattr(value, 'read'):
                        images_list.append(value)
        else:
            # Fallback: try to get from form directly
            if "images" in form:
                images_list = form.getlist("images") if hasattr(form, 'getlist') else [form["images"]]
        
        # Process images if any were found
        if images_list:
            for display_order, image_file in enumerate(images_list):
                if hasattr(image_file, 'read') and (hasattr(image_file, 'filename') and image_file.filename):
                    image_path = save_uploaded_file(image_file, "products")
                    product_image = ProductImage(
                        product_id=product.id,
                        image_url=image_path,
                        display_order=display_order
                    )
                    db.add(product_image)
    
    await db.commit()
    await db.refresh(product)
    
    # Get updated category name if category was changed
    if category_id is not None:
        result = await db.execute(select(ProductCategory).where(ProductCategory.id == product.category_id))
        updated_category = result.scalar_one_or_none()
        if updated_category:
            category_name = updated_category.name
    
    # Get first image for this product
    image_result = await db.execute(
        select(ProductImage).where(ProductImage.product_id == product.id)
        .order_by(ProductImage.display_order, ProductImage.created_at)
        .limit(1)
    )
    first_image = image_result.scalar_one_or_none()
    
    return ProductResponse(
        id=str(product.id),
        category_id=str(product.category_id),
        category_name=category_name,
        name=product.name,
        description=product.description,
        status=product.status,
        first_image=first_image.image_url if first_image else None,
        created_at=product.created_at,
        updated_at=product.updated_at
    )


@app.delete("/products/{product_id}")
async def delete_product(
    product_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Delete a product"""
    result = await db.execute(
        select(Product).where(Product.id == uuid.UUID(product_id))
    )
    product = result.scalar_one_or_none()
    
    if not product:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product {product_id} not found"
        )
    
    await db.delete(product)
    await db.commit()
    
    return {"message": "Product deleted successfully"}


# Routes - Client Products
@app.post("/client-products", response_model=ClientProductResponse, status_code=http_status.HTTP_201_CREATED)
async def attach_product_to_client(
    attachment: ClientProductAttach,
    db: AsyncSession = Depends(get_db)
):
    """Attach a product to a client"""
    # Validate product exists
    result = await db.execute(
        select(Product).where(Product.id == uuid.UUID(attachment.product_id))
    )
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product {attachment.product_id} not found"
        )
    
    # Check if already attached
    result = await db.execute(
        select(ClientProduct).where(
            and_(
                ClientProduct.client_id == attachment.client_id,
                ClientProduct.product_id == uuid.UUID(attachment.product_id)
            )
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        existing.enabled = "true" if attachment.enabled else "false"
        await db.commit()
        await db.refresh(existing)
        return ClientProductResponse(
            client_id=existing.client_id,
            product_id=str(existing.product_id),
            product_name=product.name,
            enabled=existing.enabled == "true",
            attached_at=existing.attached_at
        )
    
    new_attachment = ClientProduct(
        client_id=attachment.client_id,
        product_id=uuid.UUID(attachment.product_id),
        enabled="true" if attachment.enabled else "false"
    )
    
    db.add(new_attachment)
    await db.commit()
    await db.refresh(new_attachment)
    
    return ClientProductResponse(
        client_id=new_attachment.client_id,
        product_id=str(new_attachment.product_id),
        product_name=product.name,
        enabled=new_attachment.enabled == "true",
        attached_at=new_attachment.attached_at
    )


@app.get("/clients/{client_id}/products", response_model=List[ClientProductResponse])
async def get_client_products(
    client_id: str,
    enabled_only: bool = False,
    db: AsyncSession = Depends(get_db)
):
    """Get all products for a client"""
    query = select(ClientProduct, Product.name.label("product_name")).join(
        Product, ClientProduct.product_id == Product.id
    ).where(ClientProduct.client_id == client_id)
    
    if enabled_only:
        query = query.where(ClientProduct.enabled == "true")
    
    result = await db.execute(query)
    rows = result.all()
    
    return [
        ClientProductResponse(
            client_id=row.ClientProduct.client_id,
            product_id=str(row.ClientProduct.product_id),
            product_name=row.product_name,
            enabled=row.ClientProduct.enabled == "true",
            attached_at=row.ClientProduct.attached_at
        )
        for row in rows
    ]


@app.get("/products/{product_id}/clients")
async def get_product_clients(
    product_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get all clients for a product"""
    try:
        # Verify product exists
        product_result = await db.execute(
            select(Product).where(Product.id == uuid.UUID(product_id))
        )
        product = product_result.scalar_one_or_none()
        if not product:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Product {product_id} not found"
            )
        
        # Get all clients for this product
        # First, let's verify the product_id UUID conversion
        try:
            product_uuid = uuid.UUID(product_id)
        except ValueError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Invalid product_id UUID: {product_id} - {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid product_id format: {product_id}"
            )
        
        # Query for all ClientProduct records for this product
        query = select(ClientProduct).where(
            ClientProduct.product_id == product_uuid
        )
        result = await db.execute(query)
        client_products = result.scalars().all()  # Use scalars() to get model instances, not Row objects
        
        # Filter by enabled status - the enabled field is String in DB
        enabled_clients = [
            cp for cp in client_products 
            if str(cp.enabled).strip().lower() == "true"
        ]
        
        # Return client IDs
        client_ids = [cp.client_id for cp in enabled_clients]
        
        return {"client_ids": client_ids}
    except ValueError:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Invalid product ID format"
        )


# Routes - Product Images
@app.post("/product-images", response_model=ProductImageResponse, status_code=http_status.HTTP_201_CREATED)
async def create_product_image(
    image_data: ProductImageCreate,
    db: AsyncSession = Depends(get_db)
):
    """Add an image to a product"""
    # Validate product exists
    result = await db.execute(
        select(Product).where(Product.id == uuid.UUID(image_data.product_id))
    )
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product {image_data.product_id} not found"
        )
    
    new_image = ProductImage(
        product_id=uuid.UUID(image_data.product_id),
        image_url=image_data.image_url,
        display_order=image_data.display_order
    )
    
    db.add(new_image)
    await db.commit()
    await db.refresh(new_image)
    
    response = ProductImageResponse.model_validate(new_image)
    response.product_name = product.name
    return response


@app.get("/product-images", response_model=List[ProductImageResponse])
async def list_product_images(
    product_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List product images"""
    query = select(ProductImage, Product.name.label("product_name")).join(
        Product, ProductImage.product_id == Product.id
    )
    
    if product_id:
        query = query.where(ProductImage.product_id == uuid.UUID(product_id))
    
    query = query.order_by(ProductImage.display_order, ProductImage.created_at)
    result = await db.execute(query)
    rows = result.all()
    
    return [
        ProductImageResponse(
            id=str(row.ProductImage.id),
            product_id=str(row.ProductImage.product_id),
            product_name=row.product_name,
            image_url=row.ProductImage.image_url,
            display_order=row.ProductImage.display_order,
            created_at=row.ProductImage.created_at,
            updated_at=row.ProductImage.updated_at
        )
        for row in rows
    ]


@app.get("/product-images/{image_id}", response_model=ProductImageResponse)
async def get_product_image(image_id: str, db: AsyncSession = Depends(get_db)):
    """Get product image by ID"""
    result = await db.execute(
        select(ProductImage, Product.name.label("product_name")).join(
            Product, ProductImage.product_id == Product.id
        ).where(ProductImage.id == uuid.UUID(image_id))
    )
    row = result.first()
    
    if not row:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product image {image_id} not found"
        )
    
    return ProductImageResponse(
        id=str(row.ProductImage.id),
        product_id=str(row.ProductImage.product_id),
        product_name=row.product_name,
        image_url=row.ProductImage.image_url,
        display_order=row.ProductImage.display_order,
        created_at=row.ProductImage.created_at,
        updated_at=row.ProductImage.updated_at
    )


@app.put("/product-images/{image_id}", response_model=ProductImageResponse)
async def update_product_image(
    image_id: str,
    image_data: ProductImageUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update a product image"""
    result = await db.execute(
        select(ProductImage).where(ProductImage.id == uuid.UUID(image_id))
    )
    product_image = result.scalar_one_or_none()
    
    if not product_image:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product image {image_id} not found"
        )
    
    if image_data.image_url is not None:
        product_image.image_url = image_data.image_url
    if image_data.display_order is not None:
        product_image.display_order = image_data.display_order
    
    await db.commit()
    await db.refresh(product_image)
    
    # Get product name for response
    result = await db.execute(
        select(Product).where(Product.id == product_image.product_id)
    )
    product = result.scalar_one_or_none()
    
    response = ProductImageResponse.model_validate(product_image)
    response.product_name = product.name if product else None
    return response


@app.delete("/product-images/{image_id}", status_code=http_status.HTTP_204_NO_CONTENT)
async def delete_product_image(image_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a product image"""
    result = await db.execute(
        select(ProductImage).where(ProductImage.id == uuid.UUID(image_id))
    )
    product_image = result.scalar_one_or_none()
    
    if not product_image:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product image {image_id} not found"
        )
    
    await db.delete(product_image)
    await db.commit()
    
    return None


@app.get("/products/{product_id}/images", response_model=List[ProductImageResponse])
async def get_product_images(product_id: str, db: AsyncSession = Depends(get_db)):
    """Get all images for a specific product"""
    # Validate product exists
    result = await db.execute(
        select(Product).where(Product.id == uuid.UUID(product_id))
    )
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Product {product_id} not found"
        )
    
    result = await db.execute(
        select(ProductImage).where(ProductImage.product_id == uuid.UUID(product_id))
        .order_by(ProductImage.display_order, ProductImage.created_at)
    )
    images = result.scalars().all()
    
    return [
        ProductImageResponse(
            id=str(img.id),
            product_id=str(img.product_id),
            product_name=product.name,
            image_url=img.image_url,
            display_order=img.display_order,
            created_at=img.created_at,
            updated_at=img.updated_at
        )
        for img in images
    ]


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "product_service"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)

