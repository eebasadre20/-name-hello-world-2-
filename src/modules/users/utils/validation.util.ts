import { getRepository } from 'typeorm';
import { PasswordResetToken } from '../../entities/password_reset_tokens';
import { EmailVerificationToken } from '../../entities/email_verification_tokens';
import jwt from 'jsonwebtoken';

export interface TokenValidationResult {
  valid: boolean;
  user_id: number | null;
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
}

export interface RegisterUserRequest {
  email: string;
  password: string;
  full_name: string;
  terms_of_service_accepted: boolean;
  privacy_policy_accepted: boolean;
}

export function validateRegistrationFields(request: RegisterUserRequest): ValidationResult {
  const errors: string[] = [];

  if (!request.email) {
    errors.push('Email is required.');
  } else if (!validateEmailFormat(request.email)) {
    errors.push('Invalid email format.');
  }

  if (!request.password) {
    errors.push('Password is required.');
  } else if (!validatePasswordComplexity(request.password)) {
    errors.push('Password does not meet complexity requirements.');
  }

  if (!request.full_name) {
    errors.push('Full name is required.');
  }

  if (!request.terms_of_service_accepted) {
    errors.push('Terms of service must be accepted.');
  }

  if (!request.privacy_policy_accepted) {
    errors.push('Privacy policy must be accepted.');
  }

  return {
    isValid: errors.length === 0,
    errors: errors,
  };
}

export async function validateToken(token: string): Promise<TokenValidationResult> {
  // ... existing code
}

export function validateEmailFormat(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export function sanitizeInput(input: string): string {
  // ... existing code
}

export function validatePasswordComplexity(password: string): boolean {
  // ... existing code
}

export function comparePasswords(password: string, confirmPassword: string): boolean {
  // ... existing code
}

export function validateResetPasswordInput(token: string, password: string, password_confirmation: string): ValidationResult {
  // ... existing code
}

export async function generateEmailVerificationToken(userId: string): Promise<string> {
  // ... existing code
}
