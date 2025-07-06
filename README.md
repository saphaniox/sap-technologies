# 🚀 SAP Technologies - Full Stack Web Application

A comprehensive web application for SAP Technologies, offering web design, graphics, electrical engineering, and software solutions in Kampala, Uganda.

## 🌟 Features

- **User Authentication**: Secure signup/login system
- **Responsive Design**: Works on all devices
- **PWA Support**: Install as mobile/desktop app
- **Contact Forms**: Customer inquiry system
- **Newsletter Subscription**: Email marketing integration
- **Account Management**: User profile and settings
- **Admin Dashboard**: Manage users and content
- **Security**: Rate limiting, input validation, XSS protection

## 🛠️ Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: MongoDB Atlas
- **Authentication**: Session-based with bcrypt
- **Frontend**: HTML5, CSS3, JavaScript
- **Security**: Helmet, CORS, Rate Limiting
- **File Upload**: Multer
- **PWA**: Service Worker, Web App Manifest

## 📋 Prerequisites

- Node.js (v18 or higher)
- npm or yarn
- MongoDB Atlas account
- Git

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/sap-technologies.git
cd sap-technologies
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Environment Setup
```bash
# Copy the example environment file
cp env.example .env

# Edit .env with your actual values
# See Environment Variables section below
```

### 4. Start Development Server
```bash
npm start
```

The application will be available at `http://localhost:3000`

## 🔐 Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Database Configuration
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database_name

# Session Configuration
SESSION_SECRET=your_very_secure_session_secret_key_here

# Environment
NODE_ENV=development

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,https://your-domain.com

# Server Configuration
PORT=3000
```

### 🔒 Security Notes

- **Never commit `.env` files** to version control
- **Generate strong session secrets** for production
- **Use environment-specific configurations**
- **Keep MongoDB credentials secure**

## 📱 PWA Features

This application is a Progressive Web App (PWA) with:
- **Offline support**: Cached content available without internet
- **Install prompt**: Users can install on mobile/desktop
- **App-like experience**: Full-screen, native feel
- **Background sync**: Automatic data synchronization

### Installing as PWA
- **Android**: Chrome → Menu → "Add to Home Screen"
- **iOS**: Safari → Share → "Add to Home Screen"
- **Desktop**: Browser install prompt

## 🏗️ Project Structure

```
sap-tech-official/
├── public/                 # Static files
│   ├── images/            # Images and assets
│   ├── *.html            # HTML pages
│   ├── *.css             # Stylesheets
│   ├── *.js              # Client-side JavaScript
│   ├── manifest.json     # PWA manifest
│   └── sw.js            # Service worker
├── src/
│   └── server.js         # Main server file
├── routes/               # API routes (if separated)
├── .env                  # Environment variables (not in git)
├── .gitignore           # Git ignore rules
├── package.json         # Dependencies and scripts
└── README.md           # This file
```

## 🔧 Available Scripts

- `npm start` - Start production server
- `npm run dev` - Start development server with nodemon
- `npm run build` - Build for production (if needed)

## 🚀 Deployment

### Vercel (Recommended)
1. Push code to GitHub
2. Connect repository to Vercel
3. Add environment variables in Vercel dashboard
4. Deploy automatically

### Other Platforms
- **Railway**: Connect GitHub repo, add env vars
- **Render**: Create web service, configure environment
- **Heroku**: Use Procfile, add config vars

## 📱 Mobile & Desktop Apps

### Android APK
1. Deploy website
2. Use [PWA Builder](https://pwabuilder.com)
3. Download APK instantly

### Windows Executable
1. Use Electron (see `MOBILE_DESKTOP_GUIDE.md`)
2. Build with `npm run dist`
3. Distribute executable

## 🔒 Security Features

- **Input Validation**: Comprehensive sanitization
- **Rate Limiting**: Prevents abuse
- **CORS Protection**: Secure cross-origin requests
- **XSS Protection**: Prevents script injection
- **Session Security**: Secure cookie handling
- **Password Hashing**: bcrypt with salt rounds
- **File Upload Security**: Type and size validation

## 📊 Database Schema

### Users Collection
```javascript
{
  name: String,
  email: String (unique),
  password: String (hashed),
  profilePic: String,
  createdAt: Date,
  lastLogin: Date,
  activity: [String]
}
```

### Contact Submissions
```javascript
{
  name: String,
  email: String,
  message: String,
  submittedAt: Date,
  status: String
}
```

### Newsletter Subscribers
```javascript
{
  email: String (unique),
  subscribedAt: Date
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 📞 Support

- **Email**: info@sap-technologies.com
- **Phone**: +256 785 447 141
- **WhatsApp**: +256 706 564 628

## 🌍 About SAP Technologies

SAP Technologies is a leading technology company in Kampala, Uganda, specializing in:
- Web Design & Development
- Graphics & Logo Design
- Electrical Engineering
- Software Solutions
- Digital Platforms

**Empowering Uganda, Inspiring Africa.** 🇺🇬

---

**⚠️ Important**: Never commit sensitive information like passwords, API keys, or database credentials to version control. Always use environment variables for configuration. 