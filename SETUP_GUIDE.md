# EARN24 SG - Complete Setup & Usage Guide

## 🎯 Quick Start (5 Minutes)

### Step 1: Start the Backend Server
```bash
npm start
```

You should see:
```
✅ Successfully connected to MongoDB database.
🚀 Backend server for EARN24 SG is running on http://localhost:3001
🔒 Security features enabled: Helmet, Rate Limiting, Sanitization
✅ Admin account created successfully!
📧 Email: admin@earn24sg.com
🔑 Password: Admin@123456
```

### Step 2: Open the Application

Open these files in your web browser:

1. **Landing Page** (for new users): `index.html`
   - Register new accounts here
   - Beautiful landing page with features

2. **User Dashboard**: `dashboard.html`
   - Login as a regular user
   - View balance, complete tasks, withdraw money

3. **Admin Dashboard**: `admin.html`
   - Login with admin credentials
   - Manage users, opportunities, withdrawals

## 📖 Detailed User Guide

### For New Users

1. **Registration** (index.html)
   - Open `index.html` in your browser
   - Fill out the registration form
   - Requirements:
     - Username: 3-30 characters, letters/numbers/underscores only
     - Email: Valid email format
     - Password: At least 6 characters with uppercase, lowercase, and number
   - Click "Create Account"
   - You'll receive a $5 welcome bonus! 🎉

2. **Login** (dashboard.html)
   - Open `dashboard.html`
   - Enter your email and password
   - Click "Login"

3. **Complete Tasks**
   - Click "Earn Money" tab
   - Browse available opportunities
   - Click "Complete Task" on any opportunity
   - Money is instantly added to your balance!

4. **View Transactions**
   - Click "Transactions" tab
   - See all your earning history

5. **Withdraw Money**
   - Click "Withdraw" tab
   - Minimum withdrawal: $10
   - Choose payment method (PayPal, Bank Transfer, Gift Card)
   - Enter your account details
   - Submit request
   - Admin will process it

### For Administrators

1. **Login** (admin.html)
   - Open `admin.html`
   - Default credentials:
     - Email: `admin@earn24sg.com`
     - Password: `Admin@123456`
   - ⚠️ CHANGE THESE IN `.env` FILE!

2. **Dashboard Overview**
   - View total users, active users
   - See total opportunities
   - Monitor pending withdrawals
   - Track total earnings and withdrawals

3. **User Management**
   - Click "Users" in sidebar
   - View all registered users
   - See balance and earnings for each user
   - Activate/Deactivate user accounts

4. **Opportunity Management**
   - Click "Opportunities" in sidebar
   - View all earning opportunities
   - Create new opportunities:
     - Click "Create New"
     - Fill in title, description, reward, type
     - Click "Create"
   - Edit or delete existing opportunities
   - Toggle active/inactive status

5. **Withdrawal Processing**
   - Click "Withdrawals" in sidebar
   - View all withdrawal requests
   - For pending requests:
     - Click "Approve" to complete the withdrawal
     - Click "Reject" to refund the amount to user
   - Track processed withdrawals

## 🔧 Configuration

### Environment Variables (.env)

Important variables to configure:

```env
# Server
PORT=3001

# Database
MONGODB_URI=your_mongodb_connection_string

# Security (CHANGE THESE!)
JWT_SECRET=your_super_secret_key_here
ADMIN_EMAIL=your_admin_email@example.com
ADMIN_PASSWORD=YourStrongPassword123!

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000    # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100    # Max requests per window
```

### Customization

**To change admin credentials:**
1. Edit `.env` file
2. Update `ADMIN_EMAIL` and `ADMIN_PASSWORD`
3. Delete the admin user from database (or change password in MongoDB)
4. Restart server - new admin will be created

**To add new opportunity types:**
1. Edit `server.js`
2. Find `OpportunitySchema`
3. Add new type to enum array
4. Update frontend forms in `admin.html`

**To change minimum withdrawal amount:**
1. Edit `server.js` - line with `body('amount').isFloat({ min: 10 })`
2. Edit `dashboard.html` - update the minimum display text

## 🛡️ Security Checklist

### Before Going Live

- [ ] Change default admin password in `.env`
- [ ] Use strong JWT secret (at least 32 random characters)
- [ ] Update CORS origins to your actual domain
- [ ] Enable HTTPS/SSL
- [ ] Set `NODE_ENV=production` in `.env`
- [ ] Use production MongoDB cluster
- [ ] Set up database backups
- [ ] Configure logging service
- [ ] Test all security features
- [ ] Remove console.log statements
- [ ] Set up monitoring (e.g., PM2, New Relic)

## 🐛 Common Issues & Solutions

### Issue: "Cannot connect to database"
**Solution:**
- Check your MongoDB connection string in `.env`
- Ensure your IP is whitelisted in MongoDB Atlas
- Verify internet connection

### Issue: "Port 3001 already in use"
**Solution:**
```bash
# Windows PowerShell
Get-Process -Id (Get-NetTCPConnection -LocalPort 3001).OwningProcess | Stop-Process
```
Or change PORT in `.env` file

### Issue: "CORS error in browser"
**Solution:**
- Check CORS configuration in `server.js`
- Add your frontend URL to allowed origins
- Clear browser cache

### Issue: "Login not working"
**Solution:**
- Check if server is running
- Verify credentials
- Check browser console for errors
- Ensure token is being saved in localStorage

### Issue: "Admin can't access admin panel"
**Solution:**
- Verify you're logging in with admin account
- Check `isAdmin` field in database for that user
- Clear localStorage and login again

## 📊 Database Management

### Viewing Data in MongoDB Compass

1. Download MongoDB Compass
2. Connect using your MongoDB URI
3. Browse collections:
   - `users` - All user accounts
   - `opportunities` - All earning tasks
   - `transactions` - All financial transactions
   - `withdrawals` - All withdrawal requests

### Backup Database
```bash
# Using mongodump
mongodump --uri="your_mongodb_uri" --out=backup_folder
```

## 🚀 Deployment Guide

### Deploy to Heroku

1. Install Heroku CLI
2. Create Heroku app:
```bash
heroku create earn24sg
```

3. Set environment variables:
```bash
heroku config:set MONGODB_URI=your_uri
heroku config:set JWT_SECRET=your_secret
heroku config:set NODE_ENV=production
```

4. Deploy:
```bash
git push heroku main
```

### Deploy to VPS (Ubuntu)

1. Install Node.js and PM2
2. Clone repository
3. Install dependencies: `npm install`
4. Set up `.env` file
5. Start with PM2:
```bash
pm2 start server.js --name earn24sg
pm2 save
pm2 startup
```

6. Set up Nginx as reverse proxy
7. Configure SSL with Let's Encrypt

## 📞 Support

For questions or issues:
1. Check this guide
2. Review code comments in `server.js`
3. Check browser console for errors
4. Verify server logs

## 🎉 Success Tips

1. **Test everything** before going live
2. **Start small** - Add a few opportunities first
3. **Monitor withdrawals** - Process them promptly
4. **Engage users** - Add new opportunities regularly
5. **Security first** - Never share admin credentials
6. **Backup regularly** - Daily database backups recommended

---

**Happy earning! 💰**
