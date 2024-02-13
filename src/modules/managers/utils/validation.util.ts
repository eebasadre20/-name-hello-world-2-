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

export function validateLoginInput(email: string, password: string): ValidationResult | void {
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  // Updated password pattern to enforce a minimum of 8 characters, at least one letter, one number, and one special character
  const passwordPattern = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  let validationResult: ValidationResult = {
    isValid: true,
    message: null,
  };

  if (!emailPattern.test(email)) {
    validationResult.isValid = false;
    validationResult.message = 'Invalid email format';
    return validationResult;
  }

  if (!passwordPattern.test(password)) {
    validationResult.isValid = false;
    validationResult.message = 'Password must be at least 8 characters long and contain at least one letter, one number, and one special character';
    return validationResult;
  }

  return validationResult;
}

export function validateEmail(email: string): boolean {
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailPattern.test(email);
}

interface ValidationResult {
  isValid: boolean;
  message: string | null;
}
