import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse, SuccessResponse } from './dto/confirm-reset-password.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { LogoutManagerRequest, LogoutManagerResponse } from './dto/logout-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { sendPasswordResetEmail, sendConfirmationEmail } from './utils/email.util';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { validateLoginInput, validateLoginRequest } from './utils/validation.util';
import { comparePassword } from './utils/password.util';
import { generateTokens } from './utils/token.util';
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
    // Existing requestPasswordReset implementation
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    // Existing loginManager implementation
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
    // Note: Since the requirement specifies to send status 200 without direct output, 
    // the actual sending of the HTTP status should be handled by the controller.
    // This service method ensures the business logic is encapsulated and separated from the HTTP layer.
    return; // Adjusted to match the existing code's return type for this method.
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // Existing confirmEmail implementation
  }

  // ... other service methods
}
