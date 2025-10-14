# IMPORTANT: MongoDB Setup Required

## Your MongoDB credentials appear to be incorrect or the database hasn't been set up yet.

### Option 1: Use MongoDB Atlas (Recommended - Free)

1. **Create MongoDB Atlas Account**
   - Go to https://www.mongodb.com/cloud/atlas
   - Click "Try Free" and sign up
   - Verify your email

2. **Create a Cluster**
   - Choose FREE tier (M0 Sandbox)
   - Select a region close to Singapore
   - Click "Create Cluster"

3. **Create Database User**
   - Go to "Database Access" in left menu
   - Click "Add New Database User"
   - Choose "Password" authentication
   - Username: `earn24user`
   - Password: Create a strong password (save it!)
   - Set privileges to "Read and write to any database"
   - Click "Add User"

4. **Whitelist IP Address**
   - Go to "Network Access" in left menu
   - Click "Add IP Address"
   - Click "Allow Access from Anywhere" (for development)
   - Or add your specific IP
   - Click "Confirm"

5. **Get Connection String**
   - Go to "Database" in left menu
   - Click "Connect" on your cluster
   - Choose "Connect your application"
   - Copy the connection string
   - It looks like: `mongodb+srv://earn24user:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority`

6. **Update .env File**
   - Open `.env` file in this project
   - Replace `MONGODB_URI` with your connection string
   - Replace `<password>` with your actual password
   - Add database name: `mongodb+srv://earn24user:YOUR_PASSWORD@cluster0.xxxxx.mongodb.net/earn24sg?retryWrites=true&w=majority`

### Option 2: Use Local MongoDB (For Testing)

1. **Install MongoDB Community Server**
   - Download from https://www.mongodb.com/try/download/community
   - Install with default settings
   - MongoDB will run on `mongodb://localhost:27017`

2. **Update .env File**
   ```
   MONGODB_URI=mongodb://localhost:27017/earn24sg
   ```

### After Setting Up MongoDB

1. Update the `.env` file with correct MongoDB URI
2. Run: `npm start`
3. You should see:
   ```
   ✅ Successfully connected to MongoDB database.
   🚀 Backend server running on http://localhost:3001
   ✅ Admin account created successfully!
   ```

### Test Your Connection

Run this command to test:
```bash
node -e "const mongoose = require('mongoose'); mongoose.connect(process.env.MONGODB_URI || 'YOUR_URI_HERE').then(() => console.log('✅ Connected!')).catch(err => console.log('❌ Error:', err.message));"
```

---

**Need help? Check the MongoDB Atlas documentation: https://docs.atlas.mongodb.com/getting-started/**
