import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { LogoutManagerRequest } from './dto/logout-manager.dto';
import { ConfirmEmailRequest } from './dto/confirm-email.dto';
import { sendConfirmationEmail, sendPasswordResetEmail } from './utils/email.util';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { validateTokenExpiration } from './utils/validation.util';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  async signupManager(request: SignupManagerRequest): Promise<SignupManagerResponse> {
    // Existing signupManager code
  }

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // Existing refreshToken code
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    // Existing confirmResetPassword code
  }

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    // Existing requestPasswordReset code
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    // Existing loginManager code
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    // Existing logoutManager code
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<Manager> {
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

    const isTokenValid = validateTokenExpiration(manager.confirmation_sent_at, 24); // Assuming {{email_expired_in}} is 24 hours
    if (!isTokenValid) {
      throw new BadRequestException('Confirmation token is expired');
    }

    manager.confirmed_at = new Date();
    await this.managersRepository.save(manager);

    return manager;
  }

  // ... other service methods
}
