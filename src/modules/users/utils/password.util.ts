import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { PasswordResetToken } from 'src/entities/password_reset_tokens';

const SALT_ROUNDS = 10; // You can adjust the number of rounds as per security requirements

// The existing encryptPassword function is kept for compatibility with other parts of the codebase
export async function encryptPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  const password_hash = await bcrypt.hash(password, salt);
  return password_hash;
}

// The hashPassword function is updated to handle both new and existing code requirements
export async function hashPassword(password: string, salt?: string): Promise<string> {
  if (!salt) {
    salt = await bcrypt.genSalt(SALT_ROUNDS);
  }
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

// Updated validatePassword function to handle both new and existing code requirements
export async function validatePassword(password: string, hashedPassword?: string): Promise<boolean> {
  if (hashedPassword) {
    return bcrypt.compare(password, hashedPassword);
  } else {
    // New code validation is not needed here as it is handled by validatePasswordComplexity
    throw new Error('hashedPassword is required for validation.');
  }
}

// New function comparePasswords to fulfill the specified requirement
export async function comparePasswords(submittedPassword: string, storedPasswordHash: string): Promise<boolean> {
  return bcrypt.compare(submittedPassword, storedPasswordHash);
}

export async function generatePasswordResetToken(userId: number): Promise<PasswordResetToken> {
  const token = randomBytes(20).toString('hex');
  const expirationDate = new Date();
  expirationDate.setHours(expirationDate.getHours() + 1); // Token expires in 1 hour

  const passwordResetToken = await createPasswordResetToken({
    token,
    expires_at: expirationDate,
    user_id: userId,
  });

  return passwordResetToken;
}

// Placeholder for the actual database interaction function
async function createPasswordResetToken(data: {
  token: string;
  expires_at: Date;
  user_id: number;
}): Promise<PasswordResetToken> {
  // This function should interact with the database to create a new PasswordResetToken record
  // and return the created record.
  // The actual implementation will depend on the ORM or database interaction library used.
  throw new Error('createPasswordResetToken function is not implemented.');
}

// New function to validate password complexity
export function validatePasswordComplexity(password: string): boolean {
  const minLength = 8;
  const maxLength = 50;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecialChar = /[\^$*.[]{}()?"!@#%&/,><':;|_~`]/.test(password);

  return (
    password.length >= minLength &&
    password.length <= maxLength &&
    hasUpperCase &&
    hasLowerCase &&
    hasNumber &&
    hasSpecialChar
  );
}
