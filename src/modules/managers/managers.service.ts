import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LogoutManagerRequest, LogoutManagerResponse } from './dto/logout-manager.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { sendConfirmationEmail, sendPasswordResetEmail } from './utils/email.util';
import * as bcrypt from 'bcrypt';
import * as moment from 'moment';
import { randomBytes } from 'crypto';
import * as jwt from 'jsonwebtoken';

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

    // Here you would add the logic to either delete the token from the database
    // or add it to a blacklist, depending on your application's requirements.
    // This example assumes a function `blacklistToken` exists for demonstration purposes.
    // You would replace this with your actual implementation.
    try {
      // Assuming a function `blacklistToken` exists and takes the token and its type.
      // This is a placeholder for your actual token handling logic.
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
    // Existing loginManager implementation
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    const { token, password } = request;

    const manager = await this.managersRepository.findOne({ where: { reset_password_token: token } });
    if (!manager) {
      throw new BadRequestException('Token is not valid');
    }

    const resetPasswordExpireInHours = 1; // This value should be replaced with the actual value from your configuration
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

    // Assuming a method exists to validate the refresh token
    const isValidToken = this.validateRefreshToken(refresh_token);
    if (!isValidToken) {
      throw new BadRequestException('Refresh token is not valid');
    }

    // Assuming a method exists to delete the old refresh token
    await this.deleteOldRefreshToken(refresh_token);

    // Generate new tokens
    const newAccessToken = jwt.sign({ scope }, process.env.JWT_SECRET, { expiresIn: '24h' });
    const newRefreshToken = jwt.sign({ scope }, process.env.JWT_REFRESH_SECRET, { expiresIn: `${request.remember_in_hours}h` });

    // Assuming a method to get manager's details
    const managerDetails = await this.getManagerDetailsFromToken(refresh_token);

    const response: RefreshTokenResponse = {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      resource_owner: scope,
      resource_id: managerDetails.id,
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope: scope,
      created_at: new Date().toISOString(),
      refresh_token_expires_in: request.remember_in_hours * 3600, // Convert hours to seconds
    };

    return response;
  }

  // Placeholder for the blacklistToken function. Replace with your actual implementation.
  private async blacklistToken(token: string, type: string): Promise<void> {
    // Logic to blacklist the token
    console.log(`Blacklisting token: ${token} of type: ${type}`);
    // This is a placeholder. Implement your token blacklisting logic here.
  }

  private async validateRefreshToken(token: string): Promise<boolean> {
    // Placeholder for refresh token validation logic
    // This should interact with your token storage mechanism to validate
    return true; // This should be replaced with actual validation logic
  }

  private async deleteOldRefreshToken(token: string): Promise<void> {
    // Placeholder for logic to delete the old refresh token from storage
  }

  private async getManagerDetailsFromToken(token: string): Promise<{ id: string }> {
    // Placeholder for logic to extract manager details from the refresh token
    // This is highly dependent on how you store and manage tokens
    return { id: 'managerId' }; // This should be replaced with actual logic to extract manager ID
  }
}
