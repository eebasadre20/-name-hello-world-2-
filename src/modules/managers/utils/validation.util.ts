
export function validateTokenExpiration(sentAt: Date, emailExpiredIn: number): boolean {
  const expirationDate = new Date(sentAt);
  expirationDate.setHours(expirationDate.getHours() + emailExpiredIn);
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

export function validateConfirmEmailToken(token: string): boolean {
  // Define the expected format for the confirmation token
  // This example assumes a simpler format for demonstration purposes
  const tokenPattern = /^[A-Za-z0-9]{32}$/; // Example pattern: exactly 32 alphanumeric characters
  return tokenPattern.test(token); // Validate the token against the pattern
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

export function validateEmail(email: string): ValidationResult {
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  let validationResult: ValidationResult = {
    isValid: emailPattern.test(email),
    message: null,
  };

  if (!validationResult.isValid) {
    validationResult.message = 'Invalid email format';
  }

  return validationResult;
}

export interface ValidationResult {
  isValid: boolean,
  message: string | null,
}
