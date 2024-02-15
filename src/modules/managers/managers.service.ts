import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { validate as isEmailValid } from 'email-validator';
import { Manager } from '../../entities/managers';
import { JwtService } from '@nestjs/jwt';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LogoutManagerRequest, LogoutManagerDto } from './dto/logout-manager.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { hashPassword, comparePassword } from './utils/password.util';
import { generateAccessToken, generateRefreshToken, generateConfirmationToken } from './utils/token.util';
import { validateTokenExpiration } from './utils/validation.util';
import { ConfigService } from '@nestjs/config';
import { AccessTokenRepository } from 'src/repositories/access-tokens.repository';
import { EmailUtil } from './utils/email.util';
import config from 'src/configs';
import { RequestPasswordResetDTO } from './dto/request-password-reset.dto';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private accessTokenRepository: AccessTokenRepository,
    private refreshTokenRepository: AccessTokenRepository,
    private emailUtil: EmailUtil,
  ) {}

  async signupWithEmail(signupManagerDto: SignupManagerRequest): Promise<SignupManagerResponse> {
    // ... signupWithEmail implementation from new code
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // ... confirmEmail implementation from new code
  }

  async logoutManager(request: LogoutManagerRequest | LogoutManagerDto): Promise<void> {
    // ... logoutManager implementation from existing code
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    // ... confirmResetPassword implementation from new code
  }

  async requestPasswordReset(requestPasswordResetDto: RequestPasswordResetDTO): Promise<void> {
    // ... requestPasswordReset implementation from existing code
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
