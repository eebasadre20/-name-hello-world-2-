export function validateTokenExpiration(sentAt: Date, expiresInHours: number): boolean {
  const expirationDate = new Date(sentAt);
  expirationDate.setHours(expirationDate.getHours() + expiresInHours);
  return new Date() < expirationDate; // Correctly return true if the current time is before the expiration date
}

export function validateToken(token: string): boolean {
  // Assuming the expected token format is a JWT
  const jwtPattern = /^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/;
  return jwtPattern.test(token);
}
