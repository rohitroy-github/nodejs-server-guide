require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken");
const posts = require("./posts");

const app = express();
app.use(express.json());

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Fix: split by space

  if (!token) {
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden

    req.user = user;
    next(); // Continue to the next middleware/route
  });
}

// GET /posts - Show only posts belonging to the authenticated user
app.get("/posts", authenticateToken, (req, res) => {
  const userPosts = posts.filter(
    (post) => post.username === req.user.name
  );
  res.status(200).json(userPosts);
});

// POST /login - Generate access token
app.post("/login", (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  const user = { name: username };
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);

  res.status(200).json({ accessToken });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
