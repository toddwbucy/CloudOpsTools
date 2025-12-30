# Linux QC Patching Post - CSV Load Troubleshooting

## Issue Description
CSV file uploads successfully and appears in the dropdown, but when clicked "Load Change" button, the change doesn't actually load and enable the buttons.

## Expected Behavior
1. Upload CSV file
2. Change is saved to database
3. Change is stored in session via `set_current_change()`
4. Page reloads
5. Change is displayed as "Active Change" in the UI
6. "Confirm Connectivity" and "Run Enhanced Validation" buttons are enabled

## Debugging Steps

### Step 1: Check Browser Console
Open browser DevTools (F12) and go to Console tab. After uploading a CSV, you should see:
```
Linux QC Patching Post Tool initialized
Current change data: {id: X, change_number: "CHGXXXXX", instances: [...]}
Updating UI for loaded change: CHGXXXXX
Enabling buttons for N instances
Enabled connectivity test button
Enabled validation execution button
```

If you see `No change currently loaded` instead, the session is not persisting.

### Step 2: Check Network Tab
In browser DevTools, go to Network tab and upload a CSV. Check:

1. **Upload Request**: `POST /aws/linux-qc-patching-post/upload-change-csv`
   - Should return 200 OK
   - Response JSON should include: `{"status": "success", "change_id": X, "change_number": "CHG...", "instance_count": N}`

2. **Page Reload Request**: `GET /aws/linux-qc-patching-post/`
   - Check response HTML (Preview tab)
   - Search for `window.currentChangeData`
   - Should find: `window.currentChangeData = {"id":X,"change_number":"CHG...",...};`

### Step 3: Check Session Storage
In browser DevTools Console, run:
```javascript
// Check if change data is being passed to JavaScript
console.log(window.currentChangeData);

// Check the current change in the tool
console.log(window.getCurrentChange ? window.getCurrentChange() : 'Function not available');
```

### Step 4: Manually Test Load Change
1. Upload CSV
2. Page should reload automatically
3. If buttons are still disabled, try clicking "Load Change" manually from dropdown
4. Check console for any errors

### Common Causes

#### 1. Session Not Persisting
**Symptom**: After page reload, `window.currentChangeData` is undefined

**Causes**:
- Browser blocking cookies (check DevTools > Application > Cookies)
- Session middleware not configured correctly
- SECRET_KEY changed (invalidates existing sessions)

**Fix**:
```bash
# Clear browser cookies for localhost:8500
# Restart the application
./stop.sh && ./start.sh
```

#### 2. JavaScript Not Loading
**Symptom**: Console shows no initialization messages

**Causes**:
- JavaScript file cached with old version
- Script loading error

**Fix**:
- Hard refresh browser (Ctrl+Shift+R or Cmd+Shift+R)
- Check Network tab for 404 or 500 errors loading JS files

#### 3. Template Not Rendering Change Data
**Symptom**: `window.currentChangeData` is undefined in page source

**Causes**:
- `current_change` variable is None in template context
- Session not being read correctly

**Fix**:
Check application logs:
```bash
tail -f logs/app.log
# Look for errors related to session or change loading
```

#### 4. CSV Column Names Don't Match
**Symptom**: CSV uploads but shows "No valid instances found"

**Required CSV Columns** (case-insensitive):
- `change_number` (or `Change_number`, `ChangeNumber`)
- `instance_id` (or `InstanceID`)
- `account_id` (or `AccountID`)
- `region` (or `Region`)
- `platform` (optional, defaults to "linux")
- `name` (optional)

**Example CSV**:
```csv
change_number,instance_id,account_id,region,platform,name
CHG0012345,i-1234567890abcdef0,123456789012,us-east-1,linux,server-1
CHG0012345,i-abcdef1234567890,123456789012,us-west-2,linux,server-2
```

## Code Flow Reference

### CSV Upload Flow
1. [frontend] User selects CSV → form submit
2. [JS] `change-management.js` line 344-446: CSV upload handler
3. [backend] `linux_qc_patching_post.py` line 1228-1351: `/upload-change-csv` endpoint
   - Parses CSV
   - Creates/updates Change in database
   - Stores in session via `set_current_change()` (line 1337)
   - Returns success JSON
4. [JS] On success, page reloads (line 408)
5. [backend] `linux_qc_patching_post.py` line 307-330: Page GET handler
   - Calls `get_current_change(request)` (line 311)
   - Passes to template as `current_change` (line 324)
6. [template] `linux_qc_patching_post.html` line 259-261:
   - Sets `window.currentChangeData` if `current_change` exists
7. [JS] `linux-qc-patching-post.js` line 8:
   - Reads `window.currentChangeData`
   - Calls `updateUIForLoadedChange()` (line 21)
   - Enables buttons (lines 44-55)

### Manual Load Change Flow
1. [frontend] User selects from dropdown → clicks "Load Change"
2. [JS] `change-management.js` line 54-63: `loadSelectedChange()`
3. [JS] line 66-98: `loadChange(changeId)`
   - POST to `/load-change/{changeId}` (line 74)
4. [backend] `linux_qc_patching_post.py` line 1077-1116: `/load-change/{change_id}`
   - Queries database for change
   - Stores in session via `set_current_change()` (line 1108)
   - Returns success
5. [JS] On success, page reloads (line 89)
6. **Then follows same flow as CSV upload from step 5 onwards**

## Quick Fixes

### Fix 1: Clear and Retry
```bash
# Clear browser cache and cookies for localhost:8500
# Then retry upload
```

### Fix 2: Check Application Logs
```bash
# Check for errors
grep -i error logs/app.log | tail -20

# Check for session-related issues
grep -i session logs/app.log | tail -20
```

### Fix 3: Verify Database
```bash
# Check if change was saved
poetry run python -c "
from backend.db.session import SessionLocal
from backend.db.models.change import Change
db = SessionLocal()
changes = db.query(Change).all()
for c in changes:
    print(f'ID: {c.id}, Number: {c.change_number}, Instances: {len(c.instances)}')
"
```

### Fix 4: Test in Incognito/Private Window
Sometimes browser extensions or cached data interfere. Test in a clean browser session.

## Still Not Working?

If you've tried all the above and it's still not working:

1. **Capture full browser console output** (copy all messages)
2. **Capture network requests** (Export HAR file from DevTools > Network)
3. **Check application logs** (`logs/app.log`)
4. **Provide your CSV file format** (first 3-5 lines)

With this information, we can diagnose the exact issue.
