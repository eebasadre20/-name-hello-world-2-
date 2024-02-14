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
import { validateTokenExpiration, validateLoginRequest } from './utils/validation.util';
import { comparePassword } from './utils/password.util';
import { generateAccessToken, generateRefreshToken, generateTokens } from './utils/token.util';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  async signupManager(request: SignupManagerRequest): Promise<SignupManagerResponse> {
    // Existing code for signupManager
  }

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // Existing code for refreshToken
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<SuccessResponse | ConfirmResetPasswordResponse> {
    // Existing code for confirmResetPassword
  }

  async requestPasswordReset(email: string): Promise<SuccessResponse> {
    const manager = await this.managersRepository.findOne({ where: { email } });
    if (manager) {
      const passwordResetToken = randomBytes(32).toString('hex');
      manager.reset_password_token = passwordResetToken;
      manager.reset_password_sent_at = new Date();

      await this.managersRepository.save(manager);

      const passwordResetUrl = `http://yourfrontend.com/reset-password?reset_token=${passwordResetToken}`;
      await sendPasswordResetEmail(email, passwordResetToken, manager.name, passwordResetUrl);
    }

    return { message: "If an account with that email was found, we've sent a password reset link to it." };
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    // Existing code for loginManager
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    const { token, token_type_hint } = request;
    if (token_type_hint === 'access_token' || token_type_hint === 'refresh_token') {
      console.log(`Invalidating ${token_type_hint}: ${token}`);
    } else {
      throw new BadRequestException('Invalid token type hint');
    }
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // Existing code for confirmEmail
  }

  // ... other service methods
}
