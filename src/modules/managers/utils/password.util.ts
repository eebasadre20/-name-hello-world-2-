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
  return comparePassword(inputPassword, hashedPassword);
}
