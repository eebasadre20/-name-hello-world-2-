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
import { generateTokens, generateAccessToken, generateRefreshToken } from './utils/token.util';

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
    // Existing refreshToken implementation
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
    // Existing confirmResetPassword implementation
  }

  async requestPasswordReset(email: string): Promise<SuccessResponse> {
    // Existing requestPasswordReset implementation
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    // Existing loginManager implementation
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    const { token, token_type_hint } = request;
    // Assuming the use of a hypothetical token service for managing tokens
    if (token_type_hint === 'access_token') {
      // Here you would call your token service to blacklist the access token
      console.log(`Blacklisting access token: ${token}`);
      // Example: this.tokenService.blacklistAccessToken(token);
    } else if (token_type_hint === 'refresh_token') {
      // Here you would call your token service or directly interact with the database to delete the refresh token
      console.log(`Deleting refresh token: ${token}`);
      // Example: this.tokenService.deleteRefreshToken(token);
    } else {
      throw new BadRequestException('Invalid token type hint');
    }
    // Assuming the operation is successful, you would typically send a response back to the client.
    // However, since this is a service method, we'll assume the controller calling this service will handle the response.
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // Existing confirmEmail implementation
  }

  // ... other service methods
}
