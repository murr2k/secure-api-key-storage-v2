# Dashboard Authentication Troubleshooting Guide

## Common Issues and Solutions

### 1. Cannot Login - "Incorrect master password"

**Symptoms:**
- Login fails with "Incorrect master password" error
- You're sure you're using the right password

**Solutions:**

1. **Check .env file exists and is properly formatted:**
   ```bash
   cd dashboard/backend
   cat .env
   ```
   
   Should show:
   ```
   API_KEY_MASTER=your-actual-password
   JWT_SECRET_KEY=some-secret-key
   ```

2. **Make sure there are no quotes around the password:**
   ❌ Wrong: `API_KEY_MASTER="mypassword"`
   ✅ Correct: `API_KEY_MASTER=mypassword`

3. **Restart the backend after editing .env:**
   ```bash
   cd dashboard/backend
   # Kill the current process (Ctrl+C)
   ./start.sh
   ```

### 2. Cannot Connect to Backend

**Symptoms:**
- "Cannot connect to backend. Is it running on port 8000?"
- Health check fails

**Solutions:**

1. **Verify backend is running:**
   ```bash
   curl http://localhost:8000/api/health
   ```

2. **Check if port 8000 is already in use:**
   ```bash
   lsof -i :8000
   # or
   netstat -tulpn | grep 8000
   ```

3. **Start backend properly:**
   ```bash
   cd dashboard/backend
   ./start.sh
   ```

### 3. Environment Variables Not Loading

**Symptoms:**
- Backend shows "Master password configured: False"
- Health check shows `"master_password_set": false`

**Solutions:**

1. **Use the provided startup script:**
   ```bash
   cd dashboard/backend
   ./start.sh
   ```

2. **Or use the Python runner:**
   ```bash
   cd dashboard/backend
   python3 run_backend.py
   ```

3. **Manual start with env loading:**
   ```bash
   cd dashboard/backend
   source .env  # Load variables into shell
   export $(cat .env | grep -v '^#' | xargs)
   uvicorn main:app --reload
   ```

### 4. CORS Issues

**Symptoms:**
- Browser console shows CORS errors
- Requests blocked by CORS policy

**Solutions:**

1. **Check CORS_ORIGINS in .env:**
   ```
   CORS_ORIGINS=http://localhost:3000
   ```

2. **For multiple origins:**
   ```
   CORS_ORIGINS=http://localhost:3000,http://localhost:3001
   ```

## Quick Debug Steps

### 1. Test Backend Health
```bash
curl http://localhost:8000/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "...",
  "master_password_set": true,
  "jwt_secret_set": true,
  "storage_available": true
}
```

### 2. Test Authentication Directly
```bash
# Using the test script
cd dashboard
python3 test_auth.py

# Or manually with curl
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=your-password&grant_type=password"
```

### 3. Check Frontend Proxy
In the browser console (F12), check:
```javascript
// Should return backend health status
fetch('/api/health').then(r => r.json()).then(console.log)
```

## Complete Setup Checklist

1. **Backend Setup:**
   - [ ] Created `.env` from `.env.example`
   - [ ] Set `API_KEY_MASTER` in `.env`
   - [ ] Set `JWT_SECRET_KEY` in `.env`
   - [ ] Started backend with `./start.sh`
   - [ ] Verified health endpoint returns correct status

2. **Frontend Setup:**
   - [ ] Ran `npm install`
   - [ ] Started with `npm run dev`
   - [ ] Frontend running on http://localhost:3000

3. **Testing:**
   - [ ] Click "Test Backend Connection" on login page
   - [ ] Check browser console for errors
   - [ ] Try logging in with master password

## Debug Information

### Backend Startup Output
When backend starts correctly, you should see:
```
==================================================
Secure API Key Storage Dashboard - Backend
==================================================
Master password configured: True
JWT secret configured: True
CORS origins: http://localhost:3000
==================================================
```

### Frontend Login Flow
1. User enters password
2. Frontend sends POST to `/api/auth/login` with form data
3. Backend verifies against `API_KEY_MASTER`
4. Backend returns JWT tokens
5. Frontend stores tokens and redirects to dashboard

## Still Having Issues?

1. **Clear browser cache and cookies**
2. **Check browser console for detailed errors**
3. **Run the test script:** `python3 dashboard/test_auth.py`
4. **Check backend logs for error messages**
5. **Verify no firewall blocking port 8000**

## Example Working .env File

```bash
# dashboard/backend/.env
API_KEY_MASTER=mysecurepassword123
JWT_SECRET_KEY=your-secret-key-change-this-in-production
CORS_ORIGINS=http://localhost:3000
```

Remember: No quotes around values!