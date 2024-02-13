export function validateTokenExpiration(sentAt: Date, expiresInHours: number): boolean {
  const expirationDate = new Date(sentAt);
  expirationDate.setHours(expirationDate.getHours() + expiresInHours);
  return new Date() > expirationDate; // Correctly return true if the current time is after the expiration date, indicating the token is expired
}

export function validateToken(token: string): boolean {
  // Assuming the expected token format is a JWT
  const jwtPattern = /^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/;
  return jwtPattern.test(token);
}

export function validateLoginInput(email: string, password: string): void {
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  // Updated password pattern to enforce a minimum of 8 characters, at least one letter, one number, and one special character
  const passwordPattern = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  if (!emailPattern.test(email)) {
    throw new Error('Invalid email format');
  }

  if (!passwordPattern.test(password)) {
    throw new Error('Password must be at least 8 characters long and contain at least one letter, one number, and one special character');
  }
}
