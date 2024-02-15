import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Manager } from '../../entities/managers'; // Updated import path
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LogoutManagerRequest } from './dto/logout-manager.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { hashPassword } from './utils/password.util'; // hashPassword is now imported
import { generateConfirmationToken } from './utils/token.util';
import { validateTokenExpiration } from './utils/validation.util';
import { ConfigService } from '@nestjs/config';
import { AccessTokenRepository } from 'src/repositories/access-tokens.repository';
import { EmailUtil } from './utils/email.util'; // Added EmailUtil to the imports
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

  async signupWithEmail(signupManagerDto: SignupManagerRequest): Promise<SignupManagerResponse> {
    // Check if email is already taken
    const existingManager = await this.managersRepository.findOne({ where: { email: signupManagerDto.email } });
    if (existingManager) {
      throw new BadRequestException('Email is already taken');
    }

    // Hash the password
    const hashedPassword = await hashPassword(signupManagerDto.password);

    // Generate a confirmation token
    const confirmationToken = await generateConfirmationToken();

    // Create a new manager record
    const newManager = this.managersRepository.create({
      email: signupManagerDto.email,
      password: hashedPassword,
      confirmation_token: confirmationToken,
      confirmed_at: null,
    });

    // Save the new manager to the database
    await this.managersRepository.save(newManager);

    // Send a confirmation email
    await this.emailUtil.sendConfirmationEmail(newManager.email, confirmationToken);

    // Return the new manager
    return { user: newManager };
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

    const emailExpiredIn = this.configService.get<number>('authentication.emailExpiredIn'); // Use configService to get the expiration time
    const isTokenExpired = !validateTokenExpiration(manager.confirmation_sent_at, emailExpiredIn); // Use the retrieved value for token expiration validation
    if (isTokenExpired) {
      throw new BadRequestException('Confirmation token is expired');
    }

    manager.confirmed_at = new Date();
    await this.managersRepository.save(manager);

    return { user: manager }; // Updated to match the expected return type
  }

  // ... other service methods ...

  // Placeholder for the blacklistToken function. Replace with your actual implementation.
  private async blacklistToken(token: string, type: string): Promise<void> {
    // Logic to blacklist the token
  }

  // ... other service methods ...
}
