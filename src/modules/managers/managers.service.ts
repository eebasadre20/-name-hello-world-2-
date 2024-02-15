import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { validate as isEmailValid } from 'email-validator'; // Added email-validator import
import { Manager } from '../../entities/managers'; // Updated import path
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LogoutManagerRequest, LogoutManagerDto } from './dto/logout-manager.dto'; // Combined import for LogoutManagerRequest and LogoutManagerDto
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { hashPassword, comparePassword } from './utils/password.util'; // hashPassword and comparePassword are now imported
import { generateTokens, generateConfirmationToken } from './utils/token.util'; // Added generateTokens to the imports
import { validateEmail, validateTokenExpiration } from './utils/validation.util'; // Added validateEmail to the imports
import { ConfigService } from '@nestjs/config';
import { AccessTokenRepository } from 'src/repositories/access-tokens.repository';
import { EmailUtil } from './utils/email.util'; // Added EmailUtil to the imports
import config from 'src/configs';
import { RequestPasswordResetDTO } from './dto/request-password-reset.dto'; // Added RequestPasswordResetDTO to the imports
import * as jwt from 'jsonwebtoken'; // Added jwt import
import { randomBytes } from 'crypto'; // Added randomBytes import
import * as bcrypt from 'bcrypt'; // Added bcrypt import
import * as moment from 'moment'; // Added moment import

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
    // ... signupWithEmail implementation from new code
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // ... confirmEmail implementation from new code
  }

  async logoutManager(request: LogoutManagerRequest | LogoutManagerDto): Promise<void> {
    if (!request.token) {
      throw new BadRequestException('token is required');
    }

    // Logic to delete or blacklist the token
    if (request.token_type_hint === 'access_token') {
      // Delete or blacklist the access token
      await this.accessTokenRepository.deleteByToken(request.token);
    } else if (request.token_type_hint === 'refresh_token') {
      // Delete or blacklist the refresh token
      await this.refreshTokenRepository.deleteByRefreshToken(request.token);
    } else {
      throw new BadRequestException('Invalid token type hint provided.');
    }
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    // ... confirmResetPassword implementation from new code
  }

  async requestPasswordReset(requestPasswordResetDto: RequestPasswordResetDTO): Promise<void> {
    // ... requestPasswordReset implementation from new code
  }

  async loginManager(loginRequest: LoginRequest): Promise<LoginResponse> {
    // ... loginManager implementation from new code
  }

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // ... refreshToken implementation from new code
  }

  private async blacklistToken(token: string, type: string): Promise<void> {
    // Logic to blacklist the token
  }

  private async validateRefreshToken(token: string): Promise<boolean> {
    // Logic to validate the refresh token
    return true;
  }

  private async deleteOldRefreshToken(token: string): Promise<void> {
    // Logic to delete the old refresh token
  }

  private async getManagerDetailsFromToken(token: string): Promise<{ id: string }> {
    // Logic to get manager details from the token
    return { id: 'managerId' };
  }

  // ... other service methods ...
}
