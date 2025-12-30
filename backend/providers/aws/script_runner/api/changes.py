from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.db.models.change import Change as ChangeModel
from backend.db.models.change import ChangeInstance as ChangeInstanceModel
from backend.db.session import get_db
from backend.providers.aws.script_runner.schemas.change import (
    Change,
    ChangeCreate,
    ChangeDiff,
    ChangedInstanceDetail,
    ChangeList,
)

router = APIRouter(
    tags=["changes"],
    responses={
        404: {"description": "Not found"},
        409: {"description": "Conflict - change already exists"},
        500: {"description": "Internal server error"},
    },
)


@router.post("/", response_model=Change, status_code=status.HTTP_201_CREATED)
def create_change(change: ChangeCreate, db: Session = Depends(get_db)):
    """
    Create a new change record

    This endpoint creates a new change with its associated instances in the database.
    If the change already exists, a 409 Conflict error is returned.
    """

    # Check if change already exists
    existing = (
        db.query(ChangeModel)
        .filter(ChangeModel.change_number == change.change_number)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Change {change.change_number} already exists",
        )

    # Create new change
    db_change = ChangeModel(
        change_number=change.change_number,
        description=change.description,
        status=change.status,
        change_metadata=change.change_metadata,
    )

    # Add instances
    for instance in change.instances:
        db_instance = ChangeInstanceModel(
            instance_id=instance.instance_id,
            account_id=instance.account_id,
            region=instance.region,
            platform=instance.platform,
            instance_metadata=instance.instance_metadata,
        )
        db_change.instances.append(db_instance)  # type: ignore[attr-defined]

    db.add(db_change)
    db.commit()
    db.refresh(db_change)
    return db_change


@router.get("/", response_model=ChangeList)
def list_changes(
    change_number: Optional[str] = None,
    account_id: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """
    List changes with optional filtering

    This endpoint retrieves a list of changes with optional filtering by:
    - change_number: Exact match for change number
    - account_id: Changes that include instances with the specified AWS account ID
    - status: Change status (e.g., new, approved, completed)

    Results are paginated with skip and limit parameters.
    """

    query = db.query(ChangeModel)

    # Apply filters
    if change_number:
        query = query.filter(ChangeModel.change_number == change_number)

    if status:
        query = query.filter(ChangeModel.status == status)

    if account_id:
        # Filter by account ID using join
        query = (
            query.join(ChangeModel.instances)
            .filter(ChangeInstanceModel.account_id == account_id)
            .distinct()
        )

    # Get total count
    total = query.count()

    # Apply pagination with ordering
    # updated_at is defined as nullable=False with automatic defaults, so it should always exist
    changes = (
        query.order_by(desc(ChangeModel.updated_at)).offset(skip).limit(limit).all()
    )

    return {"changes": changes, "total": total}


@router.get("/{change_number}", response_model=Change)
def get_change(change_number: str, db: Session = Depends(get_db)):
    """
    Get a change by its change number

    This endpoint retrieves a specific change by its change number.
    If the change doesn't exist, a 404 Not Found error is returned.
    """
    change = (
        db.query(ChangeModel).filter(ChangeModel.change_number == change_number).first()
    )
    if not change:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change {change_number} not found",
        )
    return change


@router.post("/compare", response_model=ChangeDiff)
def compare_changes(change: ChangeCreate, db: Session = Depends(get_db)):
    """
    Compare a new change with an existing one

    This endpoint compares a new change with an existing one in the database.
    It identifies:
    - Added instances: Present in the new change but not in the existing one
    - Removed instances: Present in the existing change but not in the new one
    - Changed instances: Present in both but with different attributes

    If the change doesn't exist, a 404 Not Found error is returned.
    """

    # Check if change exists
    existing = (
        db.query(ChangeModel)
        .filter(ChangeModel.change_number == change.change_number)
        .first()
    )
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change {change.change_number} not found",
        )

    # Get instance IDs from existing change
    # Use a defensive approach with a default empty list
    existing_instances = getattr(existing, "instances", None) or []
    existing_instance_ids = {instance.instance_id for instance in existing_instances}
    new_instance_ids = {instance.instance_id for instance in change.instances}

    # Find differences
    added_instances = list(new_instance_ids - existing_instance_ids)
    removed_instances = list(existing_instance_ids - new_instance_ids)

    # Check for changes in existing instances
    changed_instances = []
    for new_inst in change.instances:
        if new_inst.instance_id in existing_instance_ids:
            # Use the existing_instances variable we defined above
            # Use defensive programming to handle potential data inconsistencies
            existing_inst = next(
                (i for i in existing_instances if i.instance_id == new_inst.instance_id), 
                None
            )
            
            # Skip if instance not found (shouldn't happen but be defensive)
            if existing_inst is None:
                logger.warning(f"Instance {new_inst.instance_id} not found in existing instances despite being in ID set")
                continue
            if (
                new_inst.account_id != existing_inst.account_id
                or new_inst.region != existing_inst.region
                or new_inst.platform != existing_inst.platform
            ):
                changed_instances.append(
                    ChangedInstanceDetail(
                        instance_id=new_inst.instance_id,
                        old={
                            "account_id": existing_inst.account_id,
                            "region": existing_inst.region,
                            "platform": existing_inst.platform,
                        },
                        new={
                            "account_id": new_inst.account_id,
                            "region": new_inst.region,
                            "platform": new_inst.platform,
                        },
                    )
                )

    return {
        "change_number": change.change_number,
        "existing": Change.from_orm(existing),
        "new": change,
        "added_instances": added_instances,
        "removed_instances": removed_instances,
        "changed_instances": changed_instances,
    }


@router.put("/{change_number}", response_model=Change)
def update_change(
    change_number: str, change: ChangeCreate, db: Session = Depends(get_db)
):
    """
    Update an existing change

    This endpoint updates an existing change with new data.
    If the change doesn't exist, a 404 Not Found error is returned.
    """

    existing = (
        db.query(ChangeModel).filter(ChangeModel.change_number == change_number).first()
    )
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change {change_number} not found",
        )

    # Update change fields
    existing.description = change.description
    existing.status = change.status
    existing.change_metadata = change.change_metadata
    existing.updated_at = datetime.utcnow()

    # Remove all instances and add new ones
    existing.instances.clear()  # type: ignore[attr-defined]

    for instance in change.instances:
        db_instance = ChangeInstanceModel(
            instance_id=instance.instance_id,
            account_id=instance.account_id,
            region=instance.region,
            platform=instance.platform,
            instance_metadata=instance.instance_metadata,
        )
        existing.instances.append(db_instance)  # type: ignore[attr-defined]

    db.commit()
    db.refresh(existing)
    return existing


@router.get("/{change_number}/instances", response_model=List[Dict[str, Any]])
def get_change_instances(change_number: str, db: Session = Depends(get_db)):
    """
    Get instances associated with a specific change

    This endpoint returns all instances associated with a change number.
    If the change doesn't exist, a 404 Not Found error is returned.
    """

    # Get the change
    change = (
        db.query(ChangeModel).filter(ChangeModel.change_number == change_number).first()
    )
    if not change:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Change {change_number} not found",
        )

    # Format instances for response
    instances = []
    for instance in change.instances:  # type: ignore[attr-defined]
        instances.append(
            {
                "id": instance.instance_id,
                "instance_id": instance.instance_id,
                "account_id": instance.account_id,
                "region": instance.region,
                "platform": instance.platform,
                "metadata": instance.instance_metadata or {},
            }
        )

    return instances
