import { Injectable, BadRequestException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LogoutManagerRequest, LogoutManagerResponse } from './dto/logout-manager.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { sendConfirmationEmail, sendPasswordResetEmail } from './utils/email.util';
import { hashPassword, comparePassword } from './utils/password.util';
import { generateTokens, generateConfirmationToken } from './utils/token.util';
import { validateEmail, validateTokenExpiration } from './utils/validation.util';
import { ConfigService } from '@nestjs/config';
import { AccessTokenRepository } from 'src/repositories/access-tokens.repository';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import * as moment from 'moment';
import { RequestPasswordResetDTO } from './dto/request-password-reset.dto';
import { EmailUtil } from './utils/email.util';
import config from 'src/configs';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private accessTokenRepository: AccessTokenRepository,
    private refreshTokenRepository: AccessTokenRepository, // Assuming similar repository for refresh tokens
    private emailUtil: EmailUtil, // Added EmailUtil to the constructor
  ) {}

  async signupWithEmail(signupManagerDto: SignupManagerRequest): Promise<SignupManagerResponse> {
    // ... implementation from new code
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    const { token } = request;
    const manager = await this.managersRepository.findOne({
      where: {
        confirmation_token: token,
        confirmed_at: null,
      },
    });

    if (!manager) {
      throw new BadRequestException('Confirmation token is not valid');
    }

    const emailExpiredIn = this.configService.get<number>('authentication.emailExpiredIn'); // Use configService to get the expiration time
    const isTokenExpired = !validateTokenExpiration(manager.confirmation_sent_at, emailExpiredIn); // Use the retrieved value for token expiration validation
    if (isTokenExpired) {
      throw new BadRequestException('Confirmation token is expired');
    }

    manager.confirmed_at = new Date();
    await this.managersRepository.save(manager);

    return { user: manager }; // Updated to match the expected return type
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    // ... implementation from new code
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    // ... implementation from new code
  }

  async requestPasswordReset(requestPasswordResetDto: RequestPasswordResetDTO): Promise<void> {
    // ... implementation from new code
  }

  async loginManager(loginRequest: LoginRequest): Promise<LoginResponse> {
    // ... implementation from new code
  }

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // ... implementation from new code
  }

  private async blacklistToken(token: string, type: string): Promise<void> {
    // ... implementation from new code
  }

  private async validateRefreshToken(token: string): Promise<boolean> {
    // ... implementation from new code
    return true;
  }

  private async deleteOldRefreshToken(token: string): Promise<void> {
    // ... implementation from new code
  }

  private async getManagerDetailsFromToken(token: string): Promise<{ id: string }> {
    // ... implementation from new code
    return { id: 'managerId' };
  }

  // ... other service methods including those from the existing code that are not conflicting
  // The rest of the methods from the existing code should be included here without any changes
  // as they do not conflict with the new code.
  // For example, methods like validateLoginInput should be here as they are in the existing code.
}
