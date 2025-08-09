# Vercel Deployment Instructions

## 🚀 Quick Deploy to Vercel

### Option 1: One-Click Deploy (Easiest)
1. **Push the `website` folder to a GitHub repository**
2. **Go to [vercel.com](https://vercel.com) and sign up/login**
3. **Click "New Project" and import your GitHub repository**
4. **Configure:**
   - Root Directory: `website`
   - Framework Preset: `Other`
   - Build Command: (leave empty)
   - Output Directory: `./`

### Option 2: Vercel CLI Deploy
```bash
# Navigate to website directory
cd website

# Deploy (follow prompts)
npx vercel --prod

# When prompted:
# - Set up project? Y
# - Project name: trustlens-fraud-detection
# - Directory: ./ (current)
# - Framework: Other
# - Source code location: ./
```

### Option 3: Drag & Drop Deploy
1. **Go to [vercel.com](https://vercel.com)**
2. **Drag the entire `website` folder to the deployment area**
3. **Wait for deployment to complete**

## 🔗 Expected Vercel URL Structure
Your deployed site will be available at:
- `https://trustlens-fraud-detection.vercel.app`
- `https://trustlens-fraud-detection-[random].vercel.app`

## 🧪 Test Your Deployment
Once deployed, test these URLs:
- **Main site**: `https://your-vercel-url.vercel.app/`
- **Fraud Check**: `https://your-vercel-url.vercel.app/fraudcheck.html`
- **Dashboard**: `https://your-vercel-url.vercel.app/dashboard.html`

## ✅ Verification
The frontend is already configured to automatically use:
- **Local development**: `http://localhost:3001` (your local API)
- **Production**: `https://codezilla-1-1jc8.onrender.com` (your deployed API)

## 🎯 Final Result
Once deployed, you'll have:
- **Frontend (Vercel)**: `https://your-vercel-url.vercel.app`
- **Backend (Render)**: `https://codezilla-1-1jc8.onrender.com`

The system will work seamlessly between both services!