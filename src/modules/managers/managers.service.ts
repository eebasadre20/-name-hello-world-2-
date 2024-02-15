import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LogoutManagerRequest, LogoutManagerResponse } from './dto/logout-manager.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { sendConfirmationEmail, sendPasswordResetEmail } from './utils/email.util';
import * as bcrypt from 'bcrypt';
import * as moment from 'moment';
import config from 'src/configs';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { validateLoginInput, validateEmail, validateTokenExpiration } from './utils/validation.util';
import { hashPassword, comparePassword } from './utils/password.util';
import { generateTokens, generateConfirmationToken } from './utils/token.util';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  async signupWithEmail(request: SignupManagerRequest): Promise<SignupManagerResponse> {
    const { email, password, password_confirmation } = request;

    if (!email || !password) {
      throw new BadRequestException('Missing required fields');
    }

    if (password_confirmation && password !== password_confirmation) {
      throw new BadRequestException('Password confirmation does not match');
    }

    if (!validateEmail(email)) {
      throw new BadRequestException('Invalid email format');
    }

    const passwordMinLength = config().authentication.passwordMinLength;
    if (password.length < passwordMinLength) {
      throw new BadRequestException('Password is too short');
    }

    const passwordRegex = new RegExp(config().authentication.passwordRegex);
    if (!passwordRegex.test(password)) {
      throw new BadRequestException('Password does not meet complexity requirements');
    }

    const existingManager = await this.managersRepository.findOne({ where: { email } });
    if (existingManager) {
      throw new BadRequestException('Email is already taken');
    }

    const hashedPassword = await hashPassword(password);
    const confirmationToken = await generateConfirmationToken();

    const manager = this.managersRepository.create({
      email,
      password: hashedPassword,
      confirmation_token: confirmationToken,
      confirmed_at: null,
    });
    await this.managersRepository.save(manager);

    const confirmationUrl = `http://yourfrontend.com/confirm-email?confirmation_token=${confirmationToken}`;
    await this.sendConfirmationEmail(
      email,
      confirmationToken,
      confirmationUrl,
    );

    return { user: manager };
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

    const isTokenExpired = !validateTokenExpiration(manager.confirmation_sent_at, config().authentication.confirmationIn || config().authentication.email_expired_in);
    if (isTokenExpired) {
      throw new BadRequestException('Confirmation token is expired');
    }

    manager.confirmed_at = new Date();
    await this.managersRepository.save(manager);

    return new ConfirmEmailResponse(manager);
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    // ... existing loginManager implementation
  }

  // ... other service methods including those from the existing code that are not conflicting

  private async sendConfirmationEmail(email: string, confirmationToken: string, confirmationUrl: string): Promise<void> {
    // Logic to send confirmation email
  }
}
