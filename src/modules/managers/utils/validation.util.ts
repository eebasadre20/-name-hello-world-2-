export function validateTokenExpiration(confirmationSentAt: Date, emailExpiredIn: number): boolean {
  const expirationDate = new Date(confirmationSentAt);
  expirationDate.setHours(expirationDate.getHours() + emailExpiredIn);
  return new Date() > expirationDate; // Changed the comparison operator to correctly return true if the current time is beyond the expiration date
}
