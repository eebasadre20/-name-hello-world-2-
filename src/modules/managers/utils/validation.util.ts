export function validateTokenExpiration(sentAt: Date, expiresInHours: number): boolean {
  const expirationDate = new Date(sentAt);
  expirationDate.setHours(expirationDate.getHours() + expiresInHours);
  return new Date() > expirationDate; // Correctly return true if the current time is after the expiration date, indicating the token is expired
}

export function validateToken(token: string): boolean {
  // Assuming the expected token format is a JWT
  const jwtPattern = /^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/;
  // Validate the token format and ensure it meets specific criteria such as length and character set
  if (!jwtPattern.test(token)) {
    return false; // Token does not match the JWT pattern
  }
  // Additional criteria can be added here, such as checking the token length
  if (token.length < 20 || token.length > 500) {
    return false; // Token does not meet the length criteria
  }
  return true; // Token is valid based on the given criteria
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
