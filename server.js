const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const csrf = require('csurf');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 8081;

// Security middleware for HTTP headers (OWASP A05:2024 - Security Misconfiguration)
app.use(helmet());

// Middleware for parsing form data (body-parser)
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration with secure settings (OWASP A07:2024 - Identification and Authentication Failures)
app.use(session({
    secret: '1f613322412b8d5feb42bae07d824deb7c30d8cf0924584d2ac508150874d5f40eb49d47c28e94cef30a3587afc3aa401f0b1498b42c3cadeb40b4ff4b3eb40c', // Change this secret in production (OWASP A02:2024 - Cryptographic Failures)
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false, // Should be true in production (only HTTPS), for development set to false
        httpOnly: true, // Prevents JavaScript from accessing the cookie (OWASP A07:2024)
        sameSite: 'strict' // Helps mitigate CSRF attacks (OWASP A08:2024 - Software and Data Integrity Failures)
    }
}));

// CSRF protection middleware (OWASP A08:2024 - Software and Data Integrity Failures)
const csrfProtection = csrf();
app.use(csrfProtection);

// Dummy user (for example purposes, use a database in a real-world application)
const users = [
    { username: 'user', passwordHash: bcrypt.hashSync('password', 10) }
];

// Login page
app.get('/login', (req, res) => {
    res.send(`
        <form method="post" action="/login">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
            <label>Username: <input type="text" name="username" /></label>
            <label>Password: <input type="password" name="password" /></label>
            <button type="submit">Login</button>
        </form>
    `);
});

// Login handler
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    // Password hashing and verification (OWASP A03:2024 - Injection)
    if (user && bcrypt.compareSync(password, user.passwordHash)) {
        req.session.user = user;
        res.redirect('/');
    } else {
        res.send('Invalid credentials');
    }
});

// Protected route
app.get('/', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.send(`
        <h1>Welcome ${req.session.user.username}</h1>
        <form method="post" action="/submit">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
            <label>Text: <input type="text" name="text" /></label>
            <button type="submit">Submit</button>
        </form>
        ${req.session.text ? `<p>You submitted: ${req.session.text}</p>` : ''}
    `);
});

// Form submission handler
app.post('/submit', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    req.session.text = req.body.text;
    res.redirect('/');
});

// Starting the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
