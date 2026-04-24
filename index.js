const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // Serve static files (index.html)

let db;

async function initializeDB() {
  db = await open({
    filename: './users.db',
    driver: sqlite3.Database
  });

  // Create users table if it doesn't exist
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password TEXT
    )
  `);
  console.log('Database initialized.');
}

initializeDB().catch(err => {
  console.error("Database initialization failed:", err);
});

// Signup Route
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    await db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword]);
    res.json({ message: 'User registered successfully!' });
  } catch (error) {
    if (error.message && error.message.includes('UNIQUE constraint failed')) {
      res.status(400).json({ error: 'Email already exists' });
    } else {
      console.error(error);
      res.status(500).json({ error: 'Server error' });
    }
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    res.json({ message: 'Login successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on http://0.0.0.0:${PORT}`);
});
