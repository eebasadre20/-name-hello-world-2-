import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { randomBytes } from 'crypto';
import { validate as isEmailValid } from 'email-validator';
import { Manager } from '../../entities/managers';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
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
import { SuccessResponse } from './dto/success-response.dto';
import { RequestPasswordResetDTO } from './dto/request-password-reset.dto';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
    private jwtService: JwtService,
    private configService: ConfigService,
    @InjectRepository(AccessTokenRepository)
    private accessTokenRepository: AccessTokenRepository,
    private refreshTokenRepository: AccessTokenRepository, // Assuming similar repository for refresh tokens
    private emailUtil: EmailUtil,
  ) {}

  async signupWithEmail(signupManagerDto: SignupManagerRequest): Promise<SignupManagerResponse> {
    // ... existing implementation of signupWithEmail ...
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // ... existing implementation of confirmEmail ...
  }

  async logoutManager(request: LogoutManagerRequest | LogoutManagerDto): Promise<void> {
    // ... existing implementation of logoutManager ...
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    // ... existing implementation of confirmResetPassword ...
  }

  async requestPasswordReset(requestPasswordResetDto: RequestPasswordResetDTO): Promise<SuccessResponse> {
    // ... existing implementation of requestPasswordReset ...
  }

  async loginManager(loginRequest: LoginRequest): Promise<LoginResponse> {
    if (!isEmailValid(loginRequest.email)) {
      throw new BadRequestException('Email is invalid');
    }
    if (!loginRequest.password || loginRequest.password.length < this.configService.get('PASSWORD_MIN_LENGTH')) {
      throw new BadRequestException('Password is invalid');
    }
    if (!new RegExp(this.configService.get('PASSWORD_REGEX')).test(loginRequest.password)) {
      throw new BadRequestException('Password is invalid');
    }
    if (loginRequest.grant_type === 'password' && !loginRequest.password) {
      throw new BadRequestException('password is required');
    }
    if (loginRequest.grant_type === 'refresh_token' && !loginRequest.refresh_token) {
      throw new BadRequestException('refresh_token is required');
    }

    const manager = await this.managersRepository.findOne({ where: { email: loginRequest.email } });
    if (!manager) {
      throw new BadRequestException('Email or password is not valid');
    }

    const passwordMatch = await comparePassword(loginRequest.password, manager.password);
    if (!passwordMatch) {
      throw new BadRequestException('Email or password is not valid');
    }

    const accessToken = generateAccessToken(manager);
    const refreshToken = generateRefreshToken(manager, 48); // Assuming 48 hours for refresh token expiration

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      resource_owner: 'managers',
      resource_id: manager.id,
      expires_in: 86400, // 24 hours to seconds
      token_type: 'Bearer',
      scope: loginRequest.scope,
      created_at: new Date().getTime(),
      refresh_token_expires_in: 172800, // 48 hours to seconds
    };
  }

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // ... existing implementation of refreshToken ...
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
