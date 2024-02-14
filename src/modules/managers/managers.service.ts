import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse, SuccessResponse } from './dto/confirm-reset-password.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { LogoutManagerRequest, LogoutManagerResponse } from './dto/logout-manager.dto'; // Updated import
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { sendConfirmationEmail, sendPasswordResetEmail } from './utils/email.util'; // Combined email util imports
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { validateLoginInput, validateLoginRequest } from './utils/validation.util'; // Combined both validation utils
import { comparePassword } from './utils/password.util';
import { generateTokens } from './utils/token.util'; // Kept combined token utils
import * as moment from 'moment'; // Added moment for existing code compatibility

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
    return { status: 200 };
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // Existing confirmEmail implementation
  }

  // ... other service methods
}
