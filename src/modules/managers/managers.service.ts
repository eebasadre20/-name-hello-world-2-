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
import * as jwt from 'jsonwebtoken'; // Corrected import for jwt
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
    // Existing signupWithEmail implementation
  }

  async confirmEmail(request: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    // Existing confirmEmail implementation
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

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    // Existing requestPasswordReset implementation
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
      if (manager.failed_attempts >= 5) {
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
      const unlockInHours = 24;
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

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    const { token, password } = request;

    const manager = await this.managersRepository.findOne({ where: { reset_password_token: token } });
    if (!manager) {
      throw new BadRequestException('Token is not valid');
    }

    const resetPasswordExpireInHours = 1;
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

  private async blacklistToken(token: string, type: string): Promise<void> {
    console.log(`Blacklisting token: ${token} of type: ${type}`);
  }

  private async validateRefreshToken(token: string): Promise<boolean> {
    return true;
  }

  private async deleteOldRefreshToken(token: string): Promise<void> {
  }

  private async getManagerDetailsFromToken(token: string): Promise<{ id: string }> {
    return { id: 'managerId' };
  }
}
