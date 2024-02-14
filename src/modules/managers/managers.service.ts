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
import { generateAccessToken, generateRefreshToken } from './utils/token.util';

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
    const { refresh_token, scope } = request;

    let manager;
    try {
      const decoded = jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET);
      manager = await this.managersRepository.findOne({ where: { id: decoded.id } });
      if (!manager) {
        throw new BadRequestException('Manager not found');
      }
    } catch (error) {
      throw new BadRequestException('Refresh token is not valid');
    }

    // Assuming deleteOldRefreshToken is a method that deletes the old refresh token
    // This is a placeholder for actual implementation
    // deleteOldRefreshToken(refresh_token);

    const remember_in_hours = 48; // Assuming 48 hours for refresh token expiration as a default if not provided
    const newAccessToken = generateAccessToken({ id: manager.id, email: manager.email }, '24h');
    const newRefreshToken = generateRefreshToken({ id: manager.id, email: manager.email }, `${remember_in_hours}h`);

    const response: RefreshTokenResponse = {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope: scope,
      created_at: new Date().toISOString(),
      refresh_token_expires_in: remember_in_hours * 3600, // convert hours to seconds
    };

    return response;
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

  async requestPasswordReset(email: string): Promise<SuccessResponse> {
    // Existing requestPasswordReset implementation
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    // Existing loginManager implementation
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    const { token, token_type_hint } = request;
    // Assuming the use of a hypothetical token management service for demonstration
    if (token_type_hint === 'access_token') {
      // Here you would call your token management service to blacklist the access token
      console.log(`Blacklisting access token: ${token}`);
      // Example: tokenManagementService.blacklistAccessToken(token);
    } else if (token_type_hint === 'refresh_token') {
      // Here you would call your token management service or directly interact with your database to delete the refresh token
      console.log(`Deleting refresh token: ${token}`);
      // Example: tokenManagementService.deleteRefreshToken(token);
    } else {
      throw new BadRequestException('Invalid token type hint');
    }
    // No direct output, but a success response is implied by the absence of exceptions
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // Existing confirmEmail implementation
  }

  // ... other service methods
}
