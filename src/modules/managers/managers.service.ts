import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse, SuccessResponse } from './dto/confirm-reset-password.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { LogoutManagerRequest, LogoutManagerResponse } from './dto/logout-manager.dto'; // Adjusted import for LogoutManagerResponse
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { sendPasswordResetEmail, sendConfirmationEmail } from './utils/email.util'; // Combined email util imports
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { validateLoginInput, validateLoginRequest } from './utils/validation.util'; // Combined both validation utils
import { comparePassword } from './utils/password.util';
import { generateTokens } from './utils/token.util'; // Adjusted for combined token utils
import * as moment from 'moment';

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
    // Validate the input using the DTO
    const { refresh_token, scope } = request;

    // Check if the refresh token is valid
    const manager = await this.managersRepository.findOne({ where: { refresh_token } });
    if (!manager) {
      throw new BadRequestException('Refresh token is not valid');
    }

    // Delete the old refresh token
    manager.refresh_token = null;
    await this.managersRepository.save(manager);

    // Generate new tokens
    const newAccessToken = jwt.sign({ id: manager.id, email: manager.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
    const newRefreshToken = jwt.sign({ id: manager.id, email: manager.email }, process.env.JWT_REFRESH_SECRET, { expiresIn: `${request.remember_in_hours}h` });

    // Update manager with new refresh token
    manager.refresh_token = newRefreshToken;
    await this.managersRepository.save(manager);

    // Prepare the response
    const response: RefreshTokenResponse = {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      resource_owner: scope,
      resource_id: manager.id.toString(),
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope: scope,
      created_at: new Date().toISOString(),
      refresh_token_expires_in: request.remember_in_hours * 3600, // convert hours to seconds
    };

    return response;
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<SuccessResponse | ConfirmResetPasswordResponse> {
    const manager = await this.managersRepository.findOne({ where: { reset_password_token: request.token } });
    if (!manager) {
      throw new BadRequestException('Token is not valid');
    }

    const tokenExpirationHours = 2; // Assuming 2 hours for token expiration
    const isTokenExpired = moment(manager.reset_password_sent_at).add(tokenExpirationHours, 'hours').isBefore(moment());
    if (isTokenExpired) {
      throw new BadRequestException('Token is expired');
    }

    manager.reset_password_token = null;
    manager.reset_password_sent_at = null;
    manager.password = await bcrypt.hash(request.password, 10); // Assuming bcrypt for hashing
    await this.managersRepository.save(manager);

    return { message: 'Password has been successfully reset' };
  }

  async requestPasswordReset(email: string): Promise<SuccessResponse> {
    const manager = await this.managersRepository.findOne({ where: { email } });
    if (manager) {
      const passwordResetToken = randomBytes(32).toString('hex');
      manager.reset_password_token = passwordResetToken;
      manager.reset_password_sent_at = new Date();
      await this.managersRepository.save(manager);

      // Assuming the URL to the password reset page is '/reset-password'
      const passwordResetURL = `https://yourdomain.com/reset-password?reset_token=${passwordResetToken}`;
      sendPasswordResetEmail(email, passwordResetToken, manager.name, passwordResetURL);
    }
    // Always return success response to avoid revealing email registration status
    return { message: 'If an account with that email exists, we have sent a password reset link.' };
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
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

    const tokens = generateTokens(manager.id); // Adjusted for combined token utils
    const remember_in_hours = 48; // Assuming 48 hours for refresh token expiration

    return {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope: 'managers',
      created_at: new Date().toISOString(),
      refresh_token_expires_in: remember_in_hours * 3600, // convert hours to seconds
    };
  }

  async logoutManager(request: LogoutManagerRequest): Promise<LogoutManagerResponse | void> {
    // Validate the input parameters using the DTO
    if (!request.token || !request.token_type_hint) {
      throw new BadRequestException('Token and token type hint are required');
    }
    // Depending on the project setup, here you would invalidate the token.
    // For demonstration, let's assume we're blacklisting the token.
    // This could involve adding the token to a blacklist in the database or an in-memory store like Redis.
    // Since the actual token handling is abstracted away, we'll simulate it with a placeholder function.
    // blacklistToken(request.token);

    // After invalidating the token, return a simple success response.
    return { status: 200 };
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // Existing confirmEmail implementation
  }

  // ... other service methods
}
