# Browser Debugging Steps for CSV Load Issue

## Summary
The **backend is working correctly**! The session is being set and the change data is being passed to the page. The issue is in the **browser side**.

## Confirmed Working (via curl test):
✅ Session cookie is being set correctly
✅ Change data is stored in session
✅ Page renders with `window.currentChangeData` when using the session cookie
✅ All 21 instances are in the session data

## Browser-Specific Debugging

### Step 1: Clear Browser Cache and Cookies
1. Open http://localhost:8500 in your browser
2. Press `F12` to open DevTools
3. Go to **Application** tab (Chrome) or **Storage** tab (Firefox)
4. Under **Cookies** → **http://localhost:8500**, delete the `pcm-ops-session` cookie
5. Under **Cache** → **Cache Storage**, click "Clear site data"
6. **Hard reload**: Press `Ctrl+Shift+R` (Windows/Linux) or `Cmd+Shift+R` (Mac)

### Step 2: Check if Cookie is Being Accepted
1. Open DevTools → **Application/Storage** tab
2. Go to **Cookies** → **http://localhost:8500**
3. Load a change from the dropdown (select CHG0958235 and click "Load Change")
4. Check if you see `pcm-ops-session` cookie appear
5. **If NO cookie appears**: Your browser is blocking cookies
   - Check browser privacy settings
   - Try in a different browser or incognito mode
   - Disable any privacy extensions (Privacy Badger, uBlock Origin, etc.)

### Step 3: Verify JavaScript Console
1. Open DevTools → **Console** tab
2. Refresh the page
3. Look for these messages:
   ```
   Linux QC Patching Post Tool initialized
   Current change data: {id: 2, change_number: "CHG0958235", ...}
   Updating UI for loaded change: CHG0958235
   Enabling buttons for 21 instances
   ```

4. **If you see "No change currently loaded"**:
   - The `window.currentChangeData` wasn't set
   - But we know the backend IS setting it
   - This means the page you're viewing is cached

5. **Try these fixes**:
   ```javascript
   // Paste this in the console to check:
   console.log('currentChangeData:', window.currentChangeData);

   // If undefined, check the page source:
   // View → Developer → View Source
   // Search for "currentChangeData"
   // You should see: window.currentChangeData = {JSON data};
   ```

### Step 4: Force JavaScript Reload
The JavaScript file might be cached. Try:
1. Open DevTools → **Network** tab
2. Check "Disable cache" checkbox (while DevTools is open)
3. Refresh the page (`Ctrl+R` or `Cmd+R`)
4. Look for `linux-qc-patching-post.js` in the network requests
5. Check its status code (should be 200)

### Step 5: Test in Incognito/Private Window
1. Open a new **Incognito Window** (Chrome) or **Private Window** (Firefox/Safari)
2. Navigate to http://localhost:8500/aws/linux-qc-patching-post/
3. Try loading a change
4. If it works in incognito: Your normal browser has cached data or cookie issues

### Step 6: Manual Cookie Test
In the browser console, run:
```javascript
// Check if cookies are enabled
console.log('Cookies enabled:', navigator.cookieEnabled);

// Check current cookies
console.log('Current cookies:', document.cookie);

// After loading a change, check again
console.log('After load:', document.cookie);
```

## Most Likely Cause

Based on my testing, the **#1 most likely cause** is:

### 🔴 Browser Cookie/Privacy Settings
- **Symptom**: Change loads but buttons don't enable
- **Cause**: Browser is not sending the session cookie back
- **Solution**:
  1. Check `chrome://settings/privacy` (Chrome) or `about:preferences#privacy` (Firefox)
  2. Make sure cookies are allowed for localhost
  3. Try in incognito mode
  4. Temporarily disable privacy extensions

### 🟡 JavaScript Caching
- **Symptom**: Old code running even after changes
- **Cause**: Browser cached the JS file
- **Solution**:
  1. Open DevTools
  2. Check "Disable cache" in Network tab
  3. Hard refresh (`Ctrl+Shift+R`)

## Quick Test Command

Run this in your terminal to verify the backend is working:
```bash
# This should show the change data in the HTML
curl -X POST http://localhost:8500/aws/linux-qc-patching-post/load-change/2 -c /tmp/session.txt
curl -s http://localhost:8500/aws/linux-qc-patching-post/ -b /tmp/session.txt | grep "currentChangeData"
```

If you see output, the backend is fine and it's a browser issue!

## What To Share for Further Debugging

If none of the above works, please provide:

1. **Browser Console Output** (full text from Console tab)
2. **Network Tab**:
   - Screenshot of the request to `/load-change/2`
   - Screenshot showing the response headers (especially Set-Cookie)
3. **Application/Storage Tab**:
   - Screenshot of Cookies section showing if `pcm-ops-session` exists
4. **Browser and Version**: e.g., "Chrome 120", "Firefox 121", etc.
5. **Any browser extensions** that might affect cookies/privacy

## Expected Behavior

When working correctly, you should see:

1. **Click "Load Change"** → Page reloads
2. **Page loads with**:
   - Blue info box showing "Active Change: CHG0958235"
   - "21 instances" displayed
   - "Confirm Connectivity" button ENABLED
   - "Run Enhanced Validation" button ENABLED
3. **Console shows**:
   ```
   Linux QC Patching Post Tool initialized
   Current change data: {id: 2, change_number: "CHG0958235", instances: Array(21), ...}
   Updating UI for loaded change: CHG0958235
   Enabling buttons for 21 instances
   Enabled connectivity test button
   Enabled validation execution button
   ```

That's what should happen!
