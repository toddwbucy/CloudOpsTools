"""Report generation endpoints for executions."""

import csv
import io
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from backend.db.models.execution import Execution as ExecutionModel
from backend.db.models.execution import ExecutionBatch as ExecutionBatchModel
from backend.db.session import get_db
from backend.providers.aws.script_runner.schemas.execution import ExecutionReport

# Create router
router = APIRouter()


@router.post(
    "/report",
    response_model=ExecutionReport,
    summary="Generate Execution Report",
    description="Generate a report for selected executions",
)
def generate_report(
    execution_ids: List[int] = Query(
        ..., description="List of execution IDs to include in report"
    ),
    format: str = Query("json", description="Report format: json, csv, html"),
    db: Session = Depends(get_db),
) -> Any:
    """Generate a report for selected executions."""
    # Validate format
    valid_formats = ["json", "csv", "html", "pdf"]
    if format not in valid_formats:
        raise HTTPException(
            status_code=400, detail=f"Invalid format. Must be one of: {valid_formats}"
        )

    # Get executions
    executions = (
        db.query(ExecutionModel).filter(ExecutionModel.id.in_(execution_ids)).all()
    )

    if not executions:
        raise HTTPException(
            status_code=404, detail="No executions found with provided IDs"
        )

    # Prepare report data
    results = []
    errors = []

    for execution in executions:
        instance = execution.instance
        script = execution.script

        execution_data = {
            "execution_id": execution.id,
            "instance_name": instance.name if instance else "Unknown",
            "instance_id": instance.instance_id if instance else "Unknown",
            "script_name": script.name if script else "Unknown",
            "status": execution.status,
            "result": execution.result or "",
            "ssm_status": execution.ssm_status,
            "created_at": (
                execution.created_at.isoformat() if execution.created_at else None
            ),
            "completed_at": (
                execution.execution_end_time.isoformat()
                if execution.execution_end_time
                else None
            ),
        }

        if execution.status == "failed":
            errors.append(execution_data)
        else:
            results.append(execution_data)

    # Generate report based on format
    if format == "json":
        return ExecutionReport(
            report_id=f"report_{int(datetime.utcnow().timestamp())}",
            generated_at=datetime.utcnow(),
            total_executions=len(executions),
            success_count=len(results),
            failure_count=len(errors),
            executions=executions,
            metadata={"results": results, "errors": errors},
        )
    elif format == "csv":
        return format_csv_report(results, errors)
    elif format == "html":
        return format_html_report(results, errors)
    elif format == "pdf":
        return format_pdf_report(results, errors)


def format_html_report(
    results: List[Dict[str, Any]], errors: List[Dict[str, Any]]
) -> Response:
    """Format report as HTML."""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Execution Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #666; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .success {{ color: green; }}
            .error {{ color: red; }}
            .summary {{ background-color: #f9f9f9; padding: 10px; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <h1>Execution Report</h1>
        <div class="summary">
            <p><strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()}</p>
            <p><strong>Total Executions:</strong> {len(results) + len(errors)}</p>
            <p class="success"><strong>Successful:</strong> {len(results)}</p>
            <p class="error"><strong>Failed:</strong> {len(errors)}</p>
        </div>
    """

    if results:
        html_content += """
        <h2>Successful Executions</h2>
        <table>
            <tr>
                <th>Execution ID</th>
                <th>Instance Name</th>
                <th>Script Name</th>
                <th>Status</th>
                <th>Created At</th>
                <th>Completed At</th>
            </tr>
        """
        for result in results:
            html_content += f"""
            <tr>
                <td>{escape(str(result['execution_id']))}</td>
                <td>{escape(str(result['instance_name']))}</td>
                <td>{escape(str(result['script_name']))}</td>
                <td class="success">{escape(str(result['status']))}</td>
                <td>{escape(str(result['created_at'] or 'N/A'))}</td>
                <td>{escape(str(result['completed_at'] or 'N/A'))}</td>
            </tr>
            """
        html_content += "</table>"

    if errors:
        html_content += """
        <h2>Failed Executions</h2>
        <table>
            <tr>
                <th>Execution ID</th>
                <th>Instance Name</th>
                <th>Script Name</th>
                <th>Status</th>
                <th>Error</th>
                <th>Created At</th>
            </tr>
        """
        for error in errors:
            html_content += f"""
            <tr>
                <td>{escape(str(error['execution_id']))}</td>
                <td>{escape(str(error['instance_name']))}</td>
                <td>{escape(str(error['script_name']))}</td>
                <td class="error">{escape(str(error['status']))}</td>
                <td>{escape(str(error['result']))}</td>
                <td>{escape(str(error['created_at'] or 'N/A'))}</td>
            </tr>
            """
        html_content += "</table>"

    html_content += """
    </body>
    </html>
    """

    return Response(content=html_content, media_type="text/html")


def format_csv_report(
    results: List[Dict[str, Any]], errors: List[Dict[str, Any]]
) -> Response:
    """Format report as CSV."""
    output = io.StringIO()

    # Combine results and errors
    all_executions = results + errors

    if all_executions:
        # Get all unique keys for CSV headers
        fieldnames = list(all_executions[0].keys())

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for execution in all_executions:
            writer.writerow(execution)

    csv_content = output.getvalue()
    output.close()

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=execution_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
        },
    )


def format_pdf_report(
    results: List[Dict[str, Any]], errors: List[Dict[str, Any]]
) -> Response:
    """Format report as PDF (placeholder - would require PDF library)."""
    # This would require a PDF generation library like reportlab
    # For now, return a message indicating PDF generation is not implemented
    raise HTTPException(
        status_code=501,
        detail="PDF report generation is not yet implemented. Please use JSON, CSV, or HTML format.",
    )


@router.get(
    "/batch/{batch_id}/report",
    summary="Generate Batch Report",
    description="Generate a report for all executions in a batch",
)
def generate_batch_report(
    batch_id: int,
    format: str = Query("json", description="Report format: json, csv, html"),
    db: Session = Depends(get_db),
) -> Any:
    """Generate a report for all executions in a batch."""
    # Verify batch exists
    batch = (
        db.query(ExecutionBatchModel).filter(ExecutionBatchModel.id == batch_id).first()
    )
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    # Get all execution IDs for the batch
def generate_batch_report(
    batch_id: str,
    format: str = Query("json", description="Report format: json, csv, html"),
    db: Session = Depends(get_db),
) -> Any:
    """Generate a report for all executions in a batch."""
    # Verify batch exists
    batch = (
        db.query(ExecutionBatchModel)
        .filter(ExecutionBatchModel.id == int(batch_id))
        .first()
    )
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    # Get all execution IDs for the batch
    execution_ids: List[int] = [
        e.id
        for e in db.query(ExecutionModel)
        .filter(ExecutionModel.batch_id == str(batch_id))
        .all()
        if e.id is not None
    ]

    # ... rest of function ...

    if not execution_ids:
        raise HTTPException(
            status_code=404, detail="No executions found for this batch"
        )

    # Use the existing generate_report function
    return generate_report(execution_ids=execution_ids, format=format, db=db)
