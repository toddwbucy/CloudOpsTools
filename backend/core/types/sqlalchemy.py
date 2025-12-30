"""Type definitions for SQLAlchemy models"""

from typing import (
    Any,
    Dict,
    Generic,
    List,
    Optional,
    Protocol,
    Type,
    TypeVar,
    cast,
)

from sqlalchemy.orm import Query, Session

# Define type variables for generic typing
T = TypeVar("T")
ModelType = TypeVar("ModelType")

# SQLAlchemy Column types
# Using Any to represent SQLAlchemy Column types since Column doesn't support generics
ColumnInt = Any  # Represents either Column of Integer or int value
ColumnStr = Any  # Represents either Column of String or str value
ColumnBool = Any  # Represents either Column of Boolean or bool value
ColumnDateTime = Any  # Represents either Column of DateTime or datetime value
ColumnJSON = Any  # Represents either Column of JSON or Dict value
ColumnText = Any  # Represents either Column of Text or str value

# Type for SQL filter conditions
FilterType = Dict[str, Any]


class ModelProtocol(Protocol):
    """Protocol for SQLAlchemy models"""

    id: ColumnInt

    @classmethod
    def query(cls) -> Query: ...


class CRUDBase(Generic[ModelType]):
    """Base class for CRUD operations"""

    def __init__(self, model: Type[ModelType]):
        """Initialize with SQLAlchemy model class"""
        self.model = model

    def get(self, db: Session, id: int) -> Optional[ModelType]:
        """Get a model instance by ID"""
        # Use type ignore for dynamic attribute access - model classes will have an id attribute
        result = db.query(self.model).filter(self.model.id == id).first()  # type: ignore[attr-defined]
        # Use explicit cast to fix the return type
        return cast(Optional[ModelType], result)

    def get_multi(
        self, db: Session, *, skip: int = 0, limit: int = 100
    ) -> List[ModelType]:
        """Get multiple model instances with pagination"""
        result = db.query(self.model).offset(skip).limit(limit).all()
        # Use explicit cast to fix the return type
        return cast(List[ModelType], result)

    def create(self, db: Session, *, obj_in: Dict[str, Any]) -> ModelType:
        """Create a model instance"""
        db_obj = self.model(**obj_in)
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def update(
        self, db: Session, *, db_obj: ModelType, obj_in: Dict[str, Any]
    ) -> ModelType:
        """Update a model instance"""
        for field in obj_in:
            if obj_in[field] is not None:
                setattr(db_obj, field, obj_in[field])
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def remove(self, db: Session, id: int) -> ModelType:
        """Delete a model instance"""
        obj = db.query(self.model).get(id)
        if obj is None:
            raise ValueError(f"Object with ID {id} not found")
        db.delete(obj)
        db.commit()
        # Use explicit cast to fix the return type
        return cast(ModelType, obj)
