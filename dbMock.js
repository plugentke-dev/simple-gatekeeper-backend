const bcrypt = require('bcryptjs');

// In-memory user database simulating the 'users' table in Supabase
const mockUsers = [
  {
    id: 'd8c728e8-7d49-4f7f-a6de-1b158bb6431a',
    email: 'admin@lestaz.tech',
    // Pre-hashed version of 'LestazTech2026!'
    passwordHash: '$2a$10$UoWpTz.X8VnF5dDDRiL9Eu7gLgB9wYn1XW31p3.WlD6c4.6Y1N/aC', 
    resetToken: null,
    resetTokenExpires: null
  },
  {
    id: 'f9d3a7c6-2c1b-4d5e-9f0a-8c7b6a5d4c3b',
    email: 'user@lestaz.tech',
    // Pre-hashed version of 'Password123!'
    passwordHash: '$2a$10$2lKqZ3xXb6D3JmH4hVw4euK7K7D3g9P7Vj/v3J9U4y8h1D3f4e2iS',
    resetToken: null,
    resetTokenExpires: null
  }
];

/**
 * Find a user by email
 */
async function getUserByEmail(email) {
  return mockUsers.find(u => u.email.toLowerCase() === email.toLowerCase()) || null;
}

/**
 * Find a user by reset token
 */
async function getUserByResetToken(token) {
  const user = mockUsers.find(u => u.resetToken === token);
  if (!user) return null;

  // Check token expiration
  if (user.resetTokenExpires && user.resetTokenExpires < Date.now()) {
    // Clear expired token
    user.resetToken = null;
    user.resetTokenExpires = null;
    return null;
  }
  return user;
}

/**
 * Validate a password against a user's stored hash
 */
async function validatePassword(user, password) {
  return bcrypt.compare(password, user.passwordHash);
}

/**
 * Set a password reset token for a user (valid for 1 hour)
 */
async function setResetToken(email, token) {
  const user = await getUserByEmail(email);
  if (!user) return false;

  user.resetToken = token;
  user.resetTokenExpires = Date.now() + 3600000; // 1 hour
  return true;
}

/**
 * Update user's password and clear the reset token
 */
async function updatePassword(user, newPassword) {
  const salt = await bcrypt.genSalt(10);
  user.passwordHash = await bcrypt.hash(newPassword, salt);
  user.resetToken = null;
  user.resetTokenExpires = null;
  return true;
}

module.exports = {
  getUserByEmail,
  getUserByResetToken,
  validatePassword,
  setResetToken,
  updatePassword
};
