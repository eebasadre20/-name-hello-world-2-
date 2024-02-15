import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Manager } from '../../entities/managers';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LogoutManagerRequest, LogoutManagerDto } from './dto/logout-manager.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { ConfigService } from '@nestjs/config';
import { AccessTokenRepository } from 'src/repositories/access-tokens.repository';
import { EmailUtil } from './utils/email.util';
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
    // The new code's implementation of logoutManager is not needed as it is a duplicate
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    // ... existing implementation of confirmResetPassword ...
  }

  async requestPasswordReset(requestPasswordResetDto: RequestPasswordResetDTO): Promise<SuccessResponse> {
    // ... existing implementation of requestPasswordReset ...
  }

  async loginManager(loginRequest: LoginRequest): Promise<LoginResponse> {
    // ... existing implementation of loginManager ...
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
