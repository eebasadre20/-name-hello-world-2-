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
import { validateTokenExpiration, validateLoginRequest } from './utils/validation.util';
import { comparePassword } from './utils/password.util';
import { generateAccessToken, generateRefreshToken, generateTokens } from './utils/token.util';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  // ... other service methods

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    const { token, token_type_hint } = request;
    // Assuming the existence of a method to invalidate tokens. This could be a call to a repository method or an external service.
    if (token_type_hint === 'access_token' || token_type_hint === 'refresh_token') {
      // Here you would add the logic to delete or blacklist the token.
      // This is a placeholder for demonstration. Replace it with actual logic.
      console.log(`Invalidating ${token_type_hint}: ${token}`);
      // Assuming a method exists to invalidate the token, e.g., this.tokenService.invalidateToken(token);
      // For demonstration, we're just logging the action.
    } else {
      throw new BadRequestException('Invalid token type hint');
    }
    // No direct output, but in a real scenario, you would return a response to the client indicating success.
    // For example, in a REST API built with NestJS, you might use `res.status(HttpStatus.OK).send();` in the controller.
  }

  // ... other service methods
}
