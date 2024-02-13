import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse, SuccessResponse } from './dto/confirm-reset-password.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { LogoutManagerRequest } from './dto/logout-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { sendConfirmationEmail, sendPasswordResetEmail } from './utils/email.util';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { validateTokenExpiration } from './utils/validation.util';
import { comparePassword } from './utils/password.util'; // Added from existing code
import { generateAccessToken, generateRefreshToken, generateTokens } from './utils/token.util'; // Merged new and existing code

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  async signupManager(request: SignupManagerRequest): Promise<SignupManagerResponse> {
    // Existing code remains unchanged
  }

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // Existing code remains unchanged
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<SuccessResponse> {
    const { token, password } = request;

    const manager = await this.managersRepository.findOne({ where: { reset_password_token: token } });
    if (!manager) {
      throw new BadRequestException('Token is not valid');
    }

    const resetPasswordExpireInHours = 1; // This value should be replaced with the actual value from your project configuration
    const expirationDate = new Date(manager.reset_password_sent_at);
    expirationDate.setHours(expirationDate.getHours() + resetPasswordExpireInHours);

    if (new Date() > expirationDate) {
      throw new BadRequestException('Token is expired');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    manager.reset_password_token = '';
    manager.reset_password_sent_at = null;
    manager.password = hashedPassword;

    await this.managersRepository.save(manager);

    return { message: 'Password reset successfully' };
  }

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    // Existing code remains unchanged
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    // Existing code remains unchanged
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    const { token, token_type_hint } = request;
    // Assuming the existence of a token repository or service for handling token invalidation
    if (token_type_hint === 'access_token') {
      // Invalidate the access token
      // This is a placeholder for the actual logic to invalidate the token, which might involve
      // calling a method on a repository or service that interacts with the database or cache where tokens are stored.
      console.log(`Invalidating access token: ${token}`);
    } else if (token_type_hint === 'refresh_token') {
      // Invalidate the refresh token
      // Similar to the access token, this is a placeholder for the actual logic to invalidate the refresh token.
      console.log(`Invalidating refresh token: ${token}`);
    } else {
      throw new BadRequestException('Invalid token type hint');
    }
    // No need to return anything as the function is expected to return void
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // Existing code remains unchanged
  }

  // ... other service methods
}
