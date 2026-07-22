"""
Scan Routes - Production Vulnerability Detection Endpoints
POST /scan - Full semantic analysis with LLM classification
POST /debug/scan-demo - Quick demo scan for testing
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import logging
import os

from app.api.deps import get_current_user
from semantic_engine.pipeline import get_pipeline, PipelineConfig

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])


# Request/Response schemas
class ScanRequest(BaseModel):
    """Request to scan code for vulnerabilities."""
    filename: str = Field(..., description="Name of file (e.g., 'app.py')")
    code: str = Field(..., description="Source code to analyze")
    language: str = Field(default="python", description="Programming language")
    enable_llm: bool = Field(default=True, description="Enable LLM classification")
    
    model_config = {"json_schema_extra": {
        "example": {
            "filename": "app.py",
            "code": "def query_user(user_id):\\n    query = f'SELECT * FROM users WHERE id={user_id}'\\n    cursor.execute(query)",
            "language": "python",
            "enable_llm": True
        }
    }}


class VulnerabilityDetail(BaseModel):
    """Detailed vulnerability information."""
    id: str
    type: str
    severity: str
    confidence: float
    owasp: str
    cwe: Optional[str]
    location: Dict[str, Any]
    evidence: Dict[str, Any]
    analysis: Dict[str, Any]


class ScanResponse(BaseModel):
    """Scan analysis result."""
    success: bool
    filename: str
    language: str
    analysis_time_seconds: float
    
    # Graph metrics
    graph_nodes: int
    graph_edges: int
    
    # Detection metrics
    rules_executed: int
    slices_found: int
    vulnerabilities_found: int
    
    # Results
    vulnerabilities: List[VulnerabilityDetail]
    
    # Diagnostics
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


@router.post("", response_model=ScanResponse)
async def scan_code(request: ScanRequest, user=Depends(get_current_user)):
    """
    Scan code for security vulnerabilities.
    
    **Process**:
    1. Parse code into AST
    2. Build CFG (control flow) and DFG (data flow)
    3. Create unified semantic graph
    4. Execute security query rules
    5. Extract vulnerable code slices
    6. Classify with LLM (if enabled)
    7. Return sorted vulnerabilities
    
    **Returns**:
    - Vulnerabilities with severity, confidence, location
    - LLM classification and remediation advice
    - Graph metrics and analysis time
    """
    try:
        logger.info(f"Scan request: {request.filename} ({request.language})")
        
        # Get pipeline with configuration
        config = PipelineConfig(enable_llm=request.enable_llm)
        pipeline = get_pipeline(config)
        
        # Run analysis
        result = await pipeline.analyze_code(
            filename=request.filename,
            code=request.code,
            language=request.language
        )
        
        # Build response
        response = ScanResponse(
            success=result.success,
            filename=result.filename,
            language=result.language,
            analysis_time_seconds=result.analysis_time_seconds,
            graph_nodes=result.graph_nodes,
            graph_edges=result.graph_edges,
            rules_executed=result.rules_executed,
            slices_found=result.slices_found,
            vulnerabilities_found=result.vulnerabilities_found,
            vulnerabilities=[
                VulnerabilityDetail(**v) for v in result.vulnerabilities
            ],
            warnings=result.warnings,
            errors=result.errors
        )
        
        logger.info(f"Scan complete: {result.vulnerabilities_found} vulnerabilities")
        return response
    
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )


@router.post("/demo", response_model=ScanResponse)
async def scan_demo():
    """
    Demo endpoint with pre-loaded vulnerable code.
    
    **Example**: SQL injection in Python
    
    Useful for testing the scan pipeline without providing code.
    """
    # Pre-loaded vulnerable code sample
    demo_code = """
def get_user_data(user_id):
    # VULNERABLE: SQL injection via string formatting
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def login(username, password):
    # VULNERABLE: SQL injection via concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = db.execute(query)
    return result

def search_products(category):
    # SAFE: Parameterized query
    query = "SELECT * FROM products WHERE category = ?"
    return db.execute(query, (category,))
"""
    
    request = ScanRequest(
        filename="demo_vulnerable.py",
        code=demo_code,
        language="python",
        enable_llm=True
    )
    
    return await scan_code(request)


@router.get("/health")
async def scan_health():
    """
    Check scan service health.
    
    Returns configuration and query store status.
    """
    from semantic_engine.query_store.loader import get_query_store
    
    try:
        query_store = get_query_store()
        stats = query_store.get_stats()
        
        return {
            "status": "healthy",
            "query_store": {
                "total_rules": stats["total_rules"],
                "by_severity": stats["by_severity"],
                "by_owasp": stats["by_owasp"]
            },
            "llm_enabled": get_pipeline().config.enable_llm,
            "llm_key_set": bool(os.getenv("LLM_API_KEY"))
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )
