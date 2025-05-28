// server.js
require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const posts = require("./posts");

const app = express();
app.use(express.json());

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden

    req.user = user;
    next();
  });
}

// GET /posts - Show only posts belonging to the authenticated user
app.get("/posts", authenticateToken, (req, res) => {
  const userPosts = posts.filter(post => post.username === req.user.name);
  res.status(200).json(userPosts);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Post Server is running on http://localhost:${PORT}`);
});
