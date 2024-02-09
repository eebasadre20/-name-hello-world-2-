import * as bcrypt from 'bcrypt';

export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  return hashedPassword;
}

export async function comparePassword(plainTextPassword: string, hash: string): Promise<boolean> {
  const isMatch = await bcrypt.compare(plainTextPassword, hash);
  return isMatch;
}
