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
    // ... existing signupManager code
  }

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // ... existing refreshToken code
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<SuccessResponse | ConfirmResetPasswordResponse> {
    // ... existing confirmResetPassword code
  }

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    // ... existing requestPasswordReset code
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    const { email, password } = request;

    const manager = await this.managersRepository.findOne({ where: { email } });

    if (!manager) {
      throw new BadRequestException('Email or password is not valid');
    }

    const isPasswordValid = await comparePassword(password, manager.password);
    if (!isPasswordValid) {
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

    const accessToken = generateAccessToken({ id: manager.id, email: manager.email }, '24h');
    const refreshToken = generateRefreshToken({ id: manager.id, email: manager.email }, '48h'); // Assuming remember_in_hours is 48

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope: 'managers',
      created_at: new Date().toISOString(),
      refresh_token_expires_in: 172800, // 48 hours in seconds
    };
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    const { token, token_type_hint } = request;
    // Assuming the use of a hypothetical token management service or database operation to invalidate the token
    if (token_type_hint === 'access_token') {
      // Invalidate the access token
      // This is a placeholder for the actual logic to invalidate the token, which depends on the project setup
      console.log(`Invalidating access token: ${token}`);
    } else if (token_type_hint === 'refresh_token') {
      // Invalidate the refresh token
      // This is a placeholder for the actual logic to invalidate the token, which depends on the project setup
      console.log(`Invalidating refresh token: ${token}`);
    } else {
      throw new BadRequestException('Invalid token type hint');
    }
    // No direct output, but operation success is implied by the absence of exceptions
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // ... existing confirmEmail code
  }

  // ... other service methods
}
