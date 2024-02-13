import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse, SuccessResponse } from './dto/confirm-reset-password.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { LogoutManagerRequest } from './dto/logout-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { sendConfirmationEmail, sendPasswordResetEmail } from './utils/email.util';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { validateTokenExpiration } from './utils/validation.util';
import { comparePassword } from './utils/password.util';
import { generateAccessToken, generateRefreshToken } from './utils/token.util';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  async signupManager(request: SignupManagerRequest): Promise<SignupManagerResponse> {
    const { email, password } = request;

    const existingManager = await this.managersRepository.findOne({ where: { email } });
    if (existingManager) {
      throw new BadRequestException('Email is already taken');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const confirmationToken = randomBytes(32).toString('hex');

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

  async refreshToken(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    const { refresh_token, scope } = request;

    try {
      jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET);
    } catch (error) {
      throw new BadRequestException('Refresh token is not valid');
    }

    const newAccessToken = jwt.sign({ scope }, process.env.JWT_SECRET, { expiresIn: '24h' });
    const newRefreshToken = jwt.sign({ scope }, process.env.JWT_REFRESH_SECRET, { expiresIn: `${request.remember_in_hours}h` });

    const manager = await this.managersRepository.findOne({ where: { /* logic to find manager based on refresh_token */ } });
    if (!manager) {
      throw new BadRequestException('Manager not found');
    }

    const response: RefreshTokenResponse = {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope: scope,
      created_at: new Date().toISOString(),
      refresh_token_expires_in: request.remember_in_hours * 3600,
    };

    return response;
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<SuccessResponse | ConfirmResetPasswordResponse> {
    const { token, password } = request;

    const manager = await this.managersRepository.findOne({ where: { reset_password_token: token } });
    if (!manager) {
      throw new BadRequestException('Token is not valid');
    }

    const resetPasswordExpireInHours = 1; // This value should be replaced with the actual value from your project configuration
    const expirationDate = new Date(manager.reset_password_sent_at);
    expirationDate.setHours(expirationDate.getHours() + resetPasswordExpireInHours);

    if (new Date() > expirationDate) {
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

    return { message: "Success" };
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    // Validate input
    if (!request.email || !request.password) {
      throw new BadRequestException('Email and password are required');
    }

    const manager = await this.managersRepository.findOne({ where: { email: request.email } });

    if (!manager) {
      throw new BadRequestException('Email or password is not valid');
    }

    const isPasswordValid = await comparePassword(request.password, manager.password);
    if (!isPasswordValid) {
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
      const unlockInHours = 24; // Assuming 24 is the unlock_in_hours value. Replace it with the actual value from your project configuration.
      const lockedTime = new Date(manager.locked_at).getTime();
      const currentTime = new Date().getTime();
      if (currentTime - lockedTime < unlockInHours * 60 * 60 * 1000) {
        throw new BadRequestException('User is locked');
      } else {
        manager.locked_at = null; // Unlock the manager
      }
    }

    manager.failed_attempts = 0;
    await this.managersRepository.save(manager);

    const accessToken = generateAccessToken({ id: manager.id, email: manager.email });
    const refreshToken = generateRefreshToken({ id: manager.id, email: manager.email }, 48); // Assuming 48 is the remember_in_hours value. Replace it with the actual value from your project configuration.

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope: 'managers',
      created_at: new Date().toISOString(),
      refresh_token_expires_in: 172800, // 48 hours in seconds
    };
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    const { token, token_type_hint } = request;
    if (token_type_hint === 'access_token' || token_type_hint === 'refresh_token') {
      console.log(`Blacklisting token: ${token}`);
    } else {
      throw new BadRequestException('Invalid token type hint');
    }
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

    const isTokenExpired = !validateTokenExpiration(manager.confirmation_sent_at, 24); // Assuming 24 is the email_expired_in value. Replace it with the actual value from your project configuration. Note the negation to match the function's return logic.
    if (isTokenExpired) {
      throw new BadRequestException('Confirmation token is expired');
    }

    manager.confirmed_at = new Date();
    await this.managersRepository.save(manager);

    return { user: manager }; // Updated to match the expected return type
  }

  // ... other service methods
}
