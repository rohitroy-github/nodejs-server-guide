require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");

const authApp = express();
authApp.use(express.json());

let refreshTokens = []; // In-memory refresh token store

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "25s" });
}

function generateRefreshToken(user) {
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
  refreshTokens.push(refreshToken);
  return refreshToken;
}

// POST /login - Issue tokens
authApp.post("/login", (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  const user = { name: username };
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  res.status(200).json({ accessToken, refreshToken });
});

// ✅ POST /token - Generate new access token using refresh token
authApp.post("/token", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token is required" });
  }

  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ error: "Refresh token is not valid" });
  }

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token verification failed" });

    // Issue new access token
    const accessToken = generateAccessToken({ name: user.name });
    res.status(200).json({ accessToken });
  });
});

// POST /logout - Invalidate refresh token
authApp.post("/logout", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token is required" });
  }

  refreshTokens = refreshTokens.filter(token => token !== refreshToken);
  res.status(200).json({ message: "Logged out successfully" });
});

// Start server
const PORT = process.env.AUTH_PORT || 4000;
authApp.listen(PORT, () => {
  console.log(`Auth Server is running on http://localhost:${PORT}`);
});

module.exports = authApp;
