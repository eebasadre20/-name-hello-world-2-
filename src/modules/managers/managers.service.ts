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
import { sendConfirmationEmail, sendPasswordResetEmail } from './utils/email.util'; // Combined email util imports
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { validateLoginInput, validateLoginRequest } from './utils/validation.util'; // Combined both validation utils
import { comparePassword } from './utils/password.util';
import { generateTokens } from './utils/token.util'; // Kept combined token utils

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  async signupManager(request: SignupManagerRequest): Promise<SignupManagerResponse> {
    // Existing signupManager implementation
  }

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    const isValidToken = true; // This should be replaced with actual validation logic
    if (!isValidToken) {
      throw new BadRequestException('Refresh token is not valid');
    }

    const manager = await this.managersRepository.findOne({ where: { refresh_token: request.refresh_token } });
    if (!manager) {
      throw new BadRequestException('Refresh token is not valid');
    }

    manager.refresh_token = ''; // Assuming the refresh token is stored in the manager entity
    await this.managersRepository.save(manager);

    const tokens = generateTokens(manager.id); // Use combined token generation logic for new tokens

    manager.refresh_token = tokens.refresh_token;
    await this.managersRepository.save(manager);

    const response: RefreshTokenResponse = {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope: request.scope,
      created_at: new Date().toISOString(),
      refresh_token_expires_in: request.remember_in_hours * 3600, // convert hours to seconds
    };

    return response;
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<SuccessResponse | ConfirmResetPasswordResponse> {
    // Existing confirmResetPassword implementation
  }

  async requestPasswordReset(email: string): Promise<SuccessResponse> {
    // Existing requestPasswordReset implementation
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    // Validate the login input using the updated validation logic
    const validationResult = validateLoginInput(request.email, request.password) || validateLoginRequest(request.email, request.password); // Combined both validation logics
    if (!validationResult.isValid) {
      throw new BadRequestException(validationResult.errorMessage);
    }

    const manager = await this.managersRepository.findOne({ where: { email: request.email } });

    if (!manager) {
      throw new BadRequestException('Email or password is not valid');
    }

    const passwordIsValid = await comparePassword(request.password, manager.password);
    if (!passwordIsValid) {
      manager.failed_attempts += 1;
      await this.managersRepository.save(manager);
      if (manager.failed_attempts >= 5) { // Assuming 5 is the maximum login attempts
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
      const unlockInHours = 24; // Assuming 24 hours to unlock
      const lockedTime = new Date(manager.locked_at).getTime();
      const currentTime = new Date().getTime();
      if (currentTime - lockedTime < unlockInHours * 60 * 60 * 1000) {
        throw new BadRequestException('User is locked');
      }
      manager.locked_at = null;
    }

    manager.failed_attempts = 0;
    await this.managersRepository.save(manager);

    const tokens = generateTokens(manager.id); // Use combined token generation logic
    const remember_in_hours = 48; // Assuming 48 hours for refresh token expiration

    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope: 'managers',
      created_at: new Date().toISOString(),
      refresh_token_expires_in: remember_in_hours * 3600, // convert hours to seconds
    };
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    // Existing logoutManager implementation
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // Existing confirmEmail implementation
  }

  // ... other service methods
}
