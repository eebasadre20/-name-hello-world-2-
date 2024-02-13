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
import { validateTokenExpiration, validateLoginRequest } from './utils/validation.util'; // Merged import from new and existing code
import { comparePassword } from './utils/password.util'; // Kept from existing code
import { generateAccessToken, generateRefreshToken, generateTokens } from './utils/token.util'; // Merged new and existing code

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  async signupManager(request: SignupManagerRequest): Promise<SignupManagerResponse> {
    // ... existing signupManager code
  }

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // ... existing refreshToken code
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<SuccessResponse | ConfirmResetPasswordResponse> {
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
    // ... existing requestPasswordReset code
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    const validationResult = validateLoginRequest(request.email, request.password);
    if (!validationResult.isValid) {
      throw new BadRequestException(validationResult.message);
    }

    const manager = await this.managersRepository.findOne({ where: { email: request.email } });
    if (!manager || !(await comparePassword(request.password, manager.password))) {
      manager.failed_attempts += 1;
      await this.managersRepository.save(manager);
      if (manager.failed_attempts >= 5) {
        manager.locked_at = new Date();
        manager.failed_attempts = 0;
        await this.managersRepository.save(manager);
        throw new BadRequestException('User is locked');
      }
      throw new BadRequestException('Email or password is not valid');
    }

    if (!manager.confirmed_at) {
      throw new BadRequestException('User is not confirmed');
    }

    if (manager.locked_at) {
      const unlockInHours = 24; // Assuming unlock_in_hours is 24
      const lockedTime = new Date(manager.locked_at).getTime();
      const currentTime = new Date().getTime();
      if (currentTime - lockedTime < unlockInHours * 60 * 60 * 1000) {
        throw new BadRequestException('User is locked');
      } else {
        manager.locked_at = null; // Reset locked_at if the lock period has expired
        await this.managersRepository.save(manager);
      }
    }

    manager.failed_attempts = 0;
    await this.managersRepository.save(manager);

    // Use utility function to generate tokens
    const tokens = generateTokens({ id: manager.id, email: manager.email }, '24h', 24); // Assuming generateTokens utilizes JWT_SECRET and sets expiresIn

    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: tokens.expires_in,
      token_type: 'Bearer',
      scope: 'managers',
      created_at: new Date().toISOString(),
      refresh_token_expires_in: tokens.refresh_token_expires_in,
    };
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    const { token, token_type_hint } = request;
    // Assuming the existence of a token repository or service for handling token invalidation
    if (token_type_hint === 'access_token') {
      // Invalidate the access token
      console.log(`Invalidating access token: ${token}`);
    } else if (token_type_hint === 'refresh_token') {
      // Invalidate the refresh token
      console.log(`Invalidating refresh token: ${token}`);
    } else {
      throw new BadRequestException('Invalid token type hint');
    }
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // ... existing confirmEmail code
  }

  // ... other service methods
}
