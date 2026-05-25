const supabase = require('./supabaseClient');
const bcrypt = require('bcryptjs');

// Map database snake_case object to camelCase application object
function mapUser(dbUser) {
  if (!dbUser) return null;
  return {
    id: dbUser.id,
    email: dbUser.email,
    passwordHash: dbUser.password_hash,
    resetToken: dbUser.reset_token,
    resetTokenExpires: dbUser.reset_token_expires ? new Date(dbUser.reset_token_expires).getTime() : null
  };
}

/**
 * Find a user by email
 */
async function getUserByEmail(email) {
  if (!supabase) throw new Error('Supabase client is not initialized. Check your environment variables.');
  
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email.toLowerCase())
    .maybeSingle();

  if (error) {
    console.error('Supabase error in getUserByEmail:', error);
    throw error;
  }
  return mapUser(data);
}

/**
 * Find a user by reset token
 */
async function getUserByResetToken(token) {
  if (!supabase) throw new Error('Supabase client is not initialized. Check your environment variables.');

  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('reset_token', token)
    .maybeSingle();

  if (error) {
    console.error('Supabase error in getUserByResetToken:', error);
    throw error;
  }
  if (!data) return null;

  const user = mapUser(data);

  // Check token expiration
  if (user.resetTokenExpires && user.resetTokenExpires < Date.now()) {
    // Clear expired token
    await supabase
      .from('users')
      .update({ reset_token: null, reset_token_expires: null })
      .eq('id', user.id);
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
  if (!supabase) throw new Error('Supabase client is not initialized. Check your environment variables.');

  const expiry = new Date(Date.now() + 3600000).toISOString(); // 1 hour ISO timestamp

  const { error } = await supabase
    .from('users')
    .update({ 
      reset_token: token, 
      reset_token_expires: expiry 
    })
    .eq('email', email.toLowerCase());

  if (error) {
    console.error('Supabase error in setResetToken:', error);
    throw error;
  }
  return true;
}

/**
 * Update user's password and clear the reset token
 */
async function updatePassword(user, newPassword) {
  if (!supabase) throw new Error('Supabase client is not initialized. Check your environment variables.');

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(newPassword, salt);

  const { error } = await supabase
    .from('users')
    .update({
      password_hash: hash,
      reset_token: null,
      reset_token_expires: null
    })
    .eq('id', user.id);

  if (error) {
    console.error('Supabase error in updatePassword:', error);
    throw error;
  }
  return true;
}

module.exports = {
  getUserByEmail,
  getUserByResetToken,
  validatePassword,
  setResetToken,
  updatePassword
};
