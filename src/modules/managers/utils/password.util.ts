import * as bcrypt from 'bcrypt';

export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
}

export async function comparePassword(inputPassword: string, hashedPassword: string): Promise<boolean> {
  return bcrypt.compare(inputPassword, hashedPassword);
}

// The function name is updated to match the requirement
export async function verifyPassword(inputPassword: string, hashedPassword: string): Promise<boolean> {
  // This function is essentially an alias for comparePassword, provided to match the requirement's naming convention.
  // It uses comparePassword internally to perform the comparison.
  return comparePassword(inputPassword, hashedPassword);
}
