export function validateTokenExpiration(confirmationSentAt: Date, emailExpiredIn: number): boolean {
  const expirationDate = new Date(confirmationSentAt);
  expirationDate.setHours(expirationDate.getHours() + emailExpiredIn);
  return new Date() <= expirationDate;
}
