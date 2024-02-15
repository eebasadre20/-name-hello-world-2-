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
import config from 'src/configs'; // Added import for config
import * as jwt from 'jsonwebtoken'; // Corrected import for jwt
import { randomBytes } from 'crypto';
import { validateLoginInput } from './utils/validation.util';
import { comparePassword } from './utils/password.util';
import { generateTokens } from './utils/token.util';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  async signupWithEmail(request: SignupManagerRequest): Promise<SignupManagerResponse> {
    const { email, password } = request;

    const existingManager = await this.managersRepository.findOne({ where: { email } });
    if (existingManager) {
      throw new BadRequestException('Email is already taken');
    }

    const confirmationToken = randomBytes(32).toString('hex');

    const hashedPassword = await bcrypt.hash(password, 10);

    const manager = this.managersRepository.create({
      email,
      password: hashedPassword,
      confirmation_token: confirmationToken,
      confirmed_at: null,
    });
    await this.managersRepository.save(manager);

    const confirmationUrl = `http://yourfrontend.com/confirm-email?confirmation_token=${confirmationToken}`;
    await sendConfirmationEmail(email, confirmationToken, confirmationUrl);

    return { user: manager };
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    const manager = await this.managersRepository.findOne({
      where: {
        confirmation_token: request.token,
        confirmed_at: null,
      },
    });

    if (!manager) {
      throw new BadRequestException('Confirmation token is not valid');
    }

    const emailExpiredInHours = config().authentication.confirmationIn;
    const isTokenExpired = moment(manager.confirmation_sent_at).add(emailExpiredInHours, 'hours').isBefore(moment());
    if (isTokenExpired) {
      throw new BadRequestException('Confirmation token is expired');
    }

    manager.confirmed_at = new Date();
    await this.managersRepository.save(manager);

    return new ConfirmEmailResponse(manager);
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    if (!validateLoginInput(request.email, request.password)) {
      throw new BadRequestException('Invalid email or password format');
    }

    const manager = await this.managersRepository.findOne({ where: { email: request.email } });

    if (!manager) {
      throw new BadRequestException('Email or password is not valid');
    }

    const passwordMatch = await comparePassword(request.password, manager.password);
    if (!passwordMatch) {
      manager.failed_attempts += 1;
      await this.managersRepository.save(manager);
      if (manager.failed_attempts >= 5) { // Assuming 5 as the maximum login attempts
        manager.locked_at = new Date();
        manager.failed_attempts = 0;
        await this.managersRepository.save(manager);
        throw new BadRequestException('User is locked');
      }
      throw new BadRequestException('Email or password is not valid');
    }

    if (!manager.confirmed_at) {
      throw new BadRequestException('User is not confirmed');
    }

    if (manager.locked_at) {
      const unlockInHours = 24; // Assuming 24 hours to unlock
      const lockedTime = moment(manager.locked_at);
      if (moment().diff(lockedTime, 'hours') < unlockInHours) {
        throw new BadRequestException('User is locked');
      } else {
        manager.locked_at = null;
      }
    }

    manager.failed_attempts = 0;
    await this.managersRepository.save(manager);

    const tokens = generateTokens(manager.id.toString());

    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: 86400,
      token_type: 'Bearer',
      scope: 'managers',
      created_at: new Date().toISOString(),
      refresh_token_expires_in: 72 * 3600,
    };
  }

  async logoutManager(request: LogoutManagerRequest): Promise<LogoutManagerResponse> {
    // Validate the token_type_hint to ensure it's either "access_token" or "refresh_token"
    if (!['access_token', 'refresh_token'].includes(request.token_type_hint)) {
      throw new BadRequestException('Invalid token type hint provided.');
    }

    try {
      await this.blacklistToken(request.token, request.token_type_hint);
      return { status: 200 };
    } catch (error) {
      throw new BadRequestException('Failed to logout manager.');
    }
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    const { token, password } = request;

    const manager = await this.managersRepository.findOne({ where: { reset_password_token: token } });
    if (!manager) {
      throw new BadRequestException('Token is not valid');
    }

    const resetPasswordExpireInHours = 1; // Assuming 1 hour for password reset token expiration
    const isTokenExpired = moment(manager.reset_password_sent_at).add(resetPasswordExpireInHours, 'hours').isBefore(moment());
    if (isTokenExpired) {
      throw new BadRequestException('Token is expired');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    manager.reset_password_token = '';
    manager.reset_password_sent_at = null;
    manager.password = hashedPassword;

    await this.managersRepository.save(manager);

    return { message: 'Password reset successfully' };
  }

  async requestPasswordReset(email: string): Promise<{ message: string }> {
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

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    const { refresh_token, scope } = request;

    const isValidToken = this.validateRefreshToken(refresh_token);
    if (!isValidToken) {
      throw new BadRequestException('Refresh token is not valid');
    }

    await this.deleteOldRefreshToken(refresh_token);

    const newAccessToken = jwt.sign({ scope }, process.env.JWT_SECRET, { expiresIn: '24h' });
    const newRefreshToken = jwt.sign({ scope }, process.env.JWT_REFRESH_SECRET, { expiresIn: `${request.remember_in_hours}h` });

    const managerDetails = await this.getManagerDetailsFromToken(refresh_token);

    const response: RefreshTokenResponse = {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      resource_owner: scope,
      resource_id: managerDetails.id,
      expires_in: 86400,
      token_type: 'Bearer',
      scope: scope,
      created_at: new Date().toISOString(),
      refresh_token_expires_in: request.remember_in_hours * 3600,
    };

    return response;
  }

  // Placeholder for the blacklistToken function. Replace with your actual implementation.
  private async blacklistToken(token: string, type: string): Promise<void> {
    // Logic to blacklist the token
  }

  private async validateRefreshToken(token: string): Promise<boolean> {
    // Logic to validate the refresh token
    return true; // Placeholder for actual implementation
  }

  private async deleteOldRefreshToken(token: string): Promise<void> {
    // Logic to delete the old refresh token
  }

  private async getManagerDetailsFromToken(token: string): Promise<{ id: string }> {
    // Logic to get manager details from the token
    return { id: 'managerId' }; // Placeholder for actual implementation
  }

  // ... other service methods
}
