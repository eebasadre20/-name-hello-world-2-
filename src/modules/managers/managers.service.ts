
import { Injectable, BadRequestException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LogoutManagerRequest } from './dto/logout-manager.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { sendConfirmationEmail, sendPasswordResetEmail } from './utils/email.util';
import { hashPassword, comparePassword } from './utils/password.util';
import { generateTokens, generateConfirmationToken } from './utils/token.util';
import { validateEmail, validateTokenExpiration } from './utils/validation.util';
import { ConfigService } from '@nestjs/config';
import { AccessTokenRepository } from 'src/repositories/access-tokens.repository';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
    private configService: ConfigService,
    private accessTokenRepository: AccessTokenRepository, // Added from patch
    // Placeholder for the refreshTokenRepository. Replace with your actual implementation.
    private refreshTokenRepository = new AccessTokenRepository(), // Assuming similar repository for refresh tokens
  ) {}

  async signupWithEmail(signupManagerDto: SignupManagerRequest): Promise<SignupManagerResponse> {
    // ... signupWithEmail implementation
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // ... confirmEmail implementation
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    if (!['access_token', 'refresh_token'].includes(request.token_type_hint)) {
      throw new BadRequestException('Invalid token type hint provided.');
    }

    try {
      const tokenRepository = request.token_type_hint === 'access_token' ? this.accessTokenRepository : this.refreshTokenRepository;
      await tokenRepository.delete({ token: request.token });
    } catch (error) {
      throw new BadRequestException('Failed to logout manager.');
    }
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    // ... confirmResetPassword implementation
  }

  // ... other service methods
}
