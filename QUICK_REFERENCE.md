# 📝 EARN24 SG - Quick Reference Card

## 🚀 Start Server
```bash
npm start
```

## 🌐 Access Points

| Page | File | URL | Purpose |
|------|------|-----|---------|
| Landing Page | `index.html` | Open in browser | New user registration |
| User Dashboard | `dashboard.html` | Open in browser | Member login & earning |
| Admin Panel | `admin.html` | Open in browser | Admin management |
| API Server | `server.js` | http://localhost:3001 | Backend API |

## 🔑 Default Credentials

**Admin Login:**
- Email: `admin@earn24sg.com`
- Password: `Admin@123456`

⚠️ **CHANGE THESE IN `.env` FILE!**

## 📊 User Features

| Feature | Location | Description |
|---------|----------|-------------|
| Register | `index.html` | Create new account |
| Login | `dashboard.html` | Access member area |
| View Balance | Dashboard > Overview | Check current earnings |
| Complete Tasks | Dashboard > Earn Money | Do tasks, get paid |
| View History | Dashboard > Transactions | See all transactions |
| Withdraw | Dashboard > Withdraw | Cash out (min $10) |

## 🛠️ Admin Features

| Feature | Location | Description |
|---------|----------|-------------|
| Statistics | Admin > Dashboard | View platform stats |
| Users | Admin > Users | Manage all users |
| Opportunities | Admin > Opportunities | Create/edit tasks |
| Withdrawals | Admin > Withdrawals | Process payments |
| Create Task | Admin > Opportunities > Create New | Add new opportunity |

## 💻 Commands

```bash
# Install dependencies
npm install

# Start server (production)
npm start

# Start server (development with auto-reload)
npm run dev

# Stop server on port 3001 (Windows PowerShell)
Get-Process -Id (Get-NetTCPConnection -LocalPort 3001).OwningProcess | Stop-Process -Force
```

## 🔧 Configuration Files

| File | Purpose |
|------|---------|
| `.env` | Environment variables (secrets) |
| `.env.example` | Template for .env |
| `package.json` | Dependencies & scripts |
| `server.js` | Backend logic |

## 🔐 Security Checklist

```
✅ Helmet security headers
✅ Rate limiting enabled
✅ Password hashing (bcrypt)
✅ JWT authentication
✅ Input validation
✅ NoSQL injection prevention
✅ CORS configured
✅ Environment variables
```

## 📱 API Endpoints Reference

### Public
- `POST /api/register` - Create account
- `POST /api/login` - User login
- `GET /api/opportunities` - List tasks

### User (Requires Token)
- `GET /api/user/profile` - Get profile
- `GET /api/user/transactions` - Get history
- `POST /api/tasks/complete` - Complete task
- `POST /api/withdrawal/request` - Request payout

### Admin (Requires Admin Token)
- `GET /api/admin/stats` - Dashboard stats
- `GET /api/admin/users` - List users
- `GET /api/admin/opportunities` - List all tasks
- `POST /api/admin/opportunities` - Create task
- `PUT /api/admin/opportunities/:id` - Update task
- `DELETE /api/admin/opportunities/:id` - Delete task
- `GET /api/admin/withdrawals` - List withdrawals
- `PUT /api/admin/withdrawals/:id` - Process withdrawal
- `PUT /api/admin/users/:id/toggle` - Activate/deactivate user

## 🐛 Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| Server won't start | Check `.env` file, verify MongoDB URI |
| Port in use | Kill process on port 3001 |
| Can't login | Verify server running, check credentials |
| Database error | Setup MongoDB (see MONGODB_SETUP.md) |
| CORS error | Update CORS in server.js |

## 📞 Important Links

- MongoDB Atlas: https://cloud.mongodb.com
- MongoDB Setup Guide: `MONGODB_SETUP.md`
- Full Documentation: `README.md`
- Setup Instructions: `SETUP_GUIDE.md`

## 💡 Tips

1. **Always start server first** before opening HTML files
2. **Check browser console** for frontend errors
3. **Check terminal** for backend errors
4. **Clear localStorage** if login issues persist
5. **Use browser incognito** for testing multiple accounts

## 🎯 Common Tasks

### Add New Opportunity (Admin)
1. Login to admin.html
2. Go to Opportunities
3. Click "Create New"
4. Fill form, click Create

### Process Withdrawal (Admin)
1. Login to admin.html
2. Go to Withdrawals
3. Click "Approve" or "Reject"

### User Registration
1. Open index.html
2. Fill registration form
3. Password needs: uppercase, lowercase, number
4. Get $5 welcome bonus!

### Complete Task (User)
1. Login to dashboard.html
2. Click "Earn Money"
3. Click "Complete Task"
4. Money added instantly!

## 📊 Default Settings

```
Server Port: 3001
Welcome Bonus: $5
Min Withdrawal: $10
Password Min Length: 6 chars
Rate Limit: 100 requests/15min
Auth Rate Limit: 5 attempts/15min
Token Expiry: 24 hours
```

## 🔄 Workflow

```
New User → Register (index.html)
         → Get $5 bonus
         → Login (dashboard.html)
         → Complete tasks
         → Request withdrawal
         → Admin approves
         → Get paid!
```

---

**Quick Start:** 
1. Setup MongoDB
2. Update .env
3. `npm start`
4. Open HTML files

**That's it! 🎉**
