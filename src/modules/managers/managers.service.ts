import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse, SuccessResponse } from './dto/confirm-reset-password.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { LogoutManagerRequest, LogoutManagerResponse } from './dto/logout-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { sendPasswordResetEmail, sendConfirmationEmail } from './utils/email.util';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { validateLoginInput, validateLoginRequest } from './utils/validation.util';
import { comparePassword } from './utils/password.util';
import { generateTokens } from './utils/token.util';
import * as moment from 'moment';

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

    const resetPasswordExpireInHours = 1; // Assuming 1 hour for password reset token expiration
    const isTokenExpired = moment(manager.reset_password_sent_at).add(resetPasswordExpireInHours, 'hours').isBefore(moment());
    if (isTokenExpired) {
      throw new BadRequestException('Token is expired');
    }

    manager.reset_password_token = null;
    manager.reset_password_sent_at = null;
    manager.password = await bcrypt.hash(request.password, 10); // Assuming bcrypt for password hashing
    await this.managersRepository.save(manager);

    return { message: "Password reset successfully" };
  }

  async requestPasswordReset(email: string): Promise<{ message: string } | SuccessResponse> {
    const manager = await this.managersRepository.findOne({ where: { email } });
    if (manager) {
      const passwordResetToken = randomBytes(32).toString('hex');
      manager.reset_password_token = passwordResetToken;
      manager.reset_password_sent_at = new Date();

      await this.managersRepository.save(manager);

      const passwordResetUrl = `http://yourfrontend.com/reset-password?reset_token=${passwordResetToken}`;
      await sendPasswordResetEmail(email, passwordResetToken, manager.name, passwordResetUrl);
    }

    return { message: "Password reset request processed successfully." };
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    // Existing loginManager implementation
  }

  async logoutManager(request: LogoutManagerRequest): Promise<LogoutManagerResponse | void> {
    // Existing logoutManager implementation
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // Existing confirmEmail implementation
  }

  // ... other service methods
}
