import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Manager } from 'src/entities/managers'; // Use the correct path from the existing code
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LogoutManagerRequest, LogoutManagerDto } from './dto/logout-manager.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { sendConfirmationEmail, sendPasswordResetEmail } from './utils/email.util'; // Keep the existing util functions
import { EmailUtil } from './utils/email.util'; // Added import for EmailUtil
import { hashPassword, comparePassword } from './utils/password.util';
import { generateTokens, generateConfirmationToken } from './utils/token.util';
import { validateEmail, validateTokenExpiration } from './utils/validation.util';
import { ConfigService } from '@nestjs/config';
import { AccessTokenRepository } from 'src/repositories/access-tokens.repository';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import * as bcrypt from 'bcrypt';
import * as moment from 'moment';
import { RequestPasswordResetDTO } from './dto/request-password-reset.dto';
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

  // ... other service methods from existing code

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    if (!email) {
      throw new BadRequestException('email is required');
    }
    if (!validateEmail(email)) {
      throw new BadRequestException('Email is invalid');
    }

    const manager = await this.managersRepository.findOne({ where: { email } });
    if (manager) {
      const passwordResetToken = randomBytes(32).toString('hex');
      manager.reset_password_token = passwordResetToken;
      manager.reset_password_sent_at = new Date();

      await this.managersRepository.save(manager);
      await this.emailUtil.sendPasswordResetEmail(email, passwordResetToken, manager.name);
    }

    return { message: "Password reset request processed successfully." };
  }

  // ... other service methods from existing code

  // Add any new methods from the new code that are not present in the existing code
}
