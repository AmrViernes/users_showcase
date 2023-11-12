const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 3000;

// Database setup
const db = new sqlite3.Database(':memory:'); // Use in-memory database for simplicity
db.serialize(() => {
  db.run('CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, accessToken TEXT, marketingConsent BOOLEAN)');
});

// Middleware for parsing JSON
app.use(express.json());

// Endpoint for user registration
app.post('/register', (req, res) => {
  const { email, marketingConsent } = req.body;

  // Generate id using SHA1 hash
  const id = crypto.createHash('sha1')
    .update(email + '450d0b0db2bcf4adde5032eca1a7c416e560cf44')
    .digest('hex');

  // Generate accessToken using JWT
  const accessToken = jwt.sign({ id }, 'amr');

  // Insert user into the database
  db.run('INSERT INTO users (id, email, accessToken, marketingConsent) VALUES (?, ?, ?, ?)',
    id, email, accessToken, marketingConsent);

  res.json({ id, accessToken });
});

// Endpoint for fetching user by id and accessToken
app.get('/user/:id/:accessToken', (req, res) => {
  const { id, accessToken } = req.params;

  // Verify JWT token
  jwt.verify(accessToken, 'amr', (err, decoded) => {
    if (err || decoded.id !== id) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Fetch user from the database
    db.get('SELECT * FROM users WHERE id = ?', id, (err, row) => {
      if (err || !row) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Omit email property if marketingConsent is false
      const user = {
        id: row.id,
        marketingConsent: row.marketingConsent,
      };

      if (row.marketingConsent) {
        user.email = row.email;
      }

      res.json(user);
    });
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
