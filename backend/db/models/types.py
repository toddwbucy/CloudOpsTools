"""Type helpers for SQLAlchemy models"""

from typing import Any, Generic, Type, TypeVar, cast

from sqlalchemy.orm import Session

T = TypeVar("T")


class ModelType(Generic[T]):
    """Generic type for SQLAlchemy models"""

    @classmethod
    def get_by_id(cls: Type[T], db: Session, id: int) -> T:
        """Get a model instance by ID"""
        return cast(T, db.query(cls).filter(cls.id == id).first())

    @classmethod
    def get_all(cls: Type[T], db: Session) -> list[T]:
        """Get all instances of a model"""
        return cast(list[T], db.query(cls).all())

    @classmethod
    def filter(cls: Type[T], db: Session, **kwargs: Any) -> list[T]:
        """Filter model instances by keyword arguments"""
        return cast(list[T], db.query(cls).filter_by(**kwargs).all())

    @classmethod
    def first(cls: Type[T], db: Session, **kwargs: Any) -> T:
        """Get first model instance matching keyword arguments"""
        return cast(T, db.query(cls).filter_by(**kwargs).first())
