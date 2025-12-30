# Azure Integration Plan

**Status**: Planning  
**Created**: 2025-12-03  
**Focus**: Authentication Infrastructure Only

---

## Goal

Build the complete authentication foundation for Azure - the equivalent of AWS's `CredentialManager` and `AccountManager`. This is the prerequisite for ANY Azure functionality. We must be able to reliably authenticate to both Azure Commercial and Government clouds before implementing workflows.

---

## AWS Authentication Infrastructure (Reference)

### AWS Components
1. **CredentialManager** (`backend/providers/aws/common/services/credential_manager.py`)
   - Stores credentials (access key, secret key, session token)
   - Validates credentials via STS
   - Creates boto3/aiobotocore sessions and clients
   - Supports COM and GOV environments

2. **AccountManager** (`backend/providers/aws/common/services/account_manager.py`)
   - Assumes roles into other accounts
   - Lists AWS accounts in organization
   - Lists regions
   - Manages multi-account access patterns

3. **Web UI** (`backend/web/aws/auth.py`)
   - Routes for credential input
   - Session storage with encryption
   - Boolean flags for credential status

---

## Azure Authentication Infrastructure (To Build)

### Component 1: AzureCredentialManager

**Purpose**: Core authentication service for Azure

**File**: `backend/providers/azure/common/services/credential_manager.py`

**Responsibilities**:
- Store Service Principal credentials (Tenant ID, Client ID, Client Secret)
- Validate credentials against Azure AD
- Create async credential objects for Azure SDK
- Support both Commercial and Government clouds
- Handle credential refresh/expiration

**Key Methods**:
```python
async def validate_credentials(
    tenant_id: str,
    client_id: str, 
    client_secret: str,
    cloud: str  # "commercial" or "government"
) -> bool

async def store_credentials(credentials: AzureCredentials) -> None
def get_credentials(environment: str) -> Optional[AzureCredentials]
async def create_credential(environment: str) -> ClientSecretCredential
```

**Cloud Configuration**:
```python
AZURE_CLOUDS = {
    "commercial": {
        "authority": "https://login.microsoftonline.com",
        "arm_endpoint": "https://management.azure.com",
        "portal": "portal.azure.com"
    },
    "government": {
        "authority": "https://login.microsoftonline.us",
        "arm_endpoint": "https://management.usgovcloudapi.net",
        "portal": "portal.azure.us"
    }
}
```

---

### Component 2: AzureSubscriptionManager

**Purpose**: Subscription and tenant management

**File**: `backend/providers/azure/common/services/subscription_manager.py`

**Responsibilities**:
- List all subscriptions user has access to
- Get subscription details
- List tenants (for multi-tenant scenarios)
- Validate subscription access

**Key Methods**:
```python
async def list_subscriptions(environment: str) -> List[Dict[str, Any]]
async def get_subscription(subscription_id: str, environment: str) -> Dict[str, Any]
async def validate_subscription_access(subscription_id: str, environment: str) -> bool
```

---

### Component 3: Azure Credential Schemas

**File**: `backend/providers/azure/common/schemas/credentials.py`

**Models**:
```python
class AzureCredentials(BaseModel):
    tenant_id: str
    client_id: str  # Application ID
    client_secret: str
    environment: str  # "commercial" or "government"
    expiration: Optional[float] = None
    
class AzureSubscription(BaseModel):
    subscription_id: str
    subscription_name: str
    tenant_id: str
    state: str
```

---

### Component 4: Web Authentication UI

**File**: `backend/web/azure/auth.py`

**Routes**:
- `GET /azure/credentials` - Credential management page
- `POST /azure/credentials/store` - Validate and store credentials
- `POST /azure/credentials/test` - Test credential validity
- `DELETE /azure/credentials/{environment}` - Clear credentials

**Template**: `backend/templates/azure/credentials.html`

**Session Storage** (matching AWS pattern):
- `azure_com_credentials` (boolean flag)
- `azure_gov_credentials` (boolean flag)
- `azure_com_credential_data` (encrypted credentials)
- `azure_gov_credential_data` (encrypted credentials)

---

## Proposed File Structure

```
backend/providers/azure/
├── __init__.py
├── common/
│   ├── __init__.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── credential_manager.py
│   │   └── subscription_manager.py
│   └── schemas/
│       ├── __init__.py
│       └── credentials.py
└── router.py

backend/web/azure/
├── __init__.py
└── auth.py

backend/templates/azure/
└── credentials.html
```

---

## Dependencies

Add to `pyproject.toml`:

```toml
[tool.poetry.dependencies]
# Azure authentication
azure-identity = "^1.15.0"

# Azure management libraries
azure-mgmt-subscription = "^3.1.1"
azure-mgmt-resource = "^23.0.1"

# Core Azure SDK
azure-core = "^1.29.0"
```

---

## Implementation Steps

1. **Create Directory Structure**
   - Create `backend/providers/azure/` tree
   - Create `backend/web/azure/` directory
   - Create `backend/templates/azure/` directory

2. **Implement Schemas**
   - `AzureCredentials` model
   - `AzureSubscription` model
   - Cloud configuration constants

3. **Implement AzureCredentialManager**
   - Credential validation via Azure AD
   - Credential storage (encrypted session)
   - Credential retrieval
   - Create async credential objects

4. **Implement AzureSubscriptionManager**
   - List subscriptions
   - Get subscription details
   - Validate access

5. **Build Web UI**
   - Credential input form (matching AWS style)
   - Validation endpoint
   - Storage/deletion endpoints
   - Session management

6. **Integration**
   - Register Azure routes in main app
   - Add to provider discovery
   - Test with both Com and Gov

---

## Key Differences from AWS

| Aspect | AWS | Azure |
|--------|-----|-------|
| **Credentials** | Access Key + Secret | Tenant + Client ID + Secret |
| **Auth Endpoint** | STS (regional) | Azure AD (global per cloud) |
| **Hierarchy** | Accounts | Tenants → Subscriptions |
| **Session** | Temporary credentials | Access tokens (auto-refresh) |
| **Multi-environment** | Assume role | Same credentials, different endpoints |

---

## Success Criteria

- ✅ Can input and validate Service Principal credentials for Commercial
- ✅ Can input and validate Service Principal credentials for Government
- ✅ Credentials persist in encrypted session
- ✅ Can list subscriptions in both environments
- ✅ Web UI matches AWS credential UI patterns
- ✅ Session management mirrors AWS implementation

---

## Open Questions

1. **Multi-tenant Support**: Should one credential set support multiple tenants?
2. **Token Caching**: Should we cache Azure AD tokens or let SDK handle it?
3. **Government Testing**: Do you have Gov tenant access for testing?

---

## Future Phases (Post-Authentication)

Once authentication is solid, future work includes:
- Azure VM listing and management
- Azure Run Command executor (equivalent to AWS SSM)
- Linux Patching tools for Azure
- Cross-cloud unified workflows
