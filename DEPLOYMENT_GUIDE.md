# TrustLens Deployment Guide

## 🚀 Deploy Backend to Render

### Step 1: Push to GitHub
```bash
# Initialize git repository if not already done
git init
git add .
git commit -m "Initial commit - TrustLens fraud detection system"

# Push to your GitHub repository
git branch -M main
git remote add origin https://github.com/yourusername/trustlens-fraud-detection.git
git push -u origin main
```

### Step 2: Deploy on Render
1. Go to [render.com](https://render.com) and sign up/login
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: `trustlens-fraud-api`
   - **Root Directory**: `API`
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free

5. Add Environment Variables:
   - `NODE_ENV`: `production`
   - `MONGO_URI`: `mongodb://localhost:27017` (or your MongoDB Atlas URL)
   - `MONGO_DB_NAME`: `fraud_detection`
   - `MONGO_COLLECTION_NAME`: `transactions`
   - `TWILIO_ACCOUNT_SID`: `AC32971a3cf32a20364bc2f0e6e8bfeb06`
   - `TWILIO_AUTH_TOKEN`: `00217da82ce538e5a5aea68cd8077490`
   - `TWILIO_NUMBER`: `+12025550123`

6. Click "Create Web Service"

### Expected Backend URL: 
`https://trustlens-fraud-api.onrender.com`

---

## 🌐 Deploy Frontend to Vercel

### Step 1: Install Vercel CLI (if not installed)
```bash
npm install -g vercel
```

### Step 2: Deploy to Vercel
```bash
# Navigate to website directory
cd website

# Login to Vercel (if not already logged in)
vercel login

# Deploy
vercel --prod
```

### Step 3: Configure Vercel Project
1. Project name: `trustlens-fraud-detection`
2. Framework: `Other`
3. Root Directory: `./` (current directory)
4. Build Command: (leave empty)
5. Output Directory: `./` (current directory)

---

## 🔧 Post-Deployment Updates

### Update API URLs (if needed)
If your Render backend URL is different from `https://trustlens-fraud-api.onrender.com`, update these files:

1. **fraudcheck.html** - Line ~295:
```javascript
const API_BASE = window.location.hostname === 'localhost' 
    ? 'http://localhost:3001' 
    : 'https://YOUR-ACTUAL-RENDER-URL.onrender.com';
```

2. **dashboard.html** - Line ~682:
```javascript
const API_BASE_URL = window.location.hostname === 'localhost' 
    ? 'http://localhost:3001' 
    : 'https://YOUR-ACTUAL-RENDER-URL.onrender.com';
```

---

## 🧪 Test Deployment

### Test Backend API:
```bash
curl https://YOUR-RENDER-URL.onrender.com/data
```

### Test Frontend:
1. Visit your Vercel URL
2. Navigate to `/fraudcheck.html`
3. Submit a test transaction
4. Verify fraud detection works

---

## 📋 Quick Commands Summary

```bash
# 1. Deploy Backend to Render (via GitHub)
git add . && git commit -m "Deploy to Render" && git push

# 2. Deploy Frontend to Vercel
cd website && vercel --prod

# 3. Test API
curl https://YOUR-RENDER-URL.onrender.com/anomalous
```

## 🔗 Expected Live URLs

- **Frontend (Vercel)**: `https://trustlens-fraud-detection.vercel.app`
- **Backend (Render)**: `https://trustlens-fraud-api.onrender.com`

The system will automatically detect the environment and use the correct API endpoints!