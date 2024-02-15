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

  // ... other service methods

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

    const emailExpiredInHours = 24; // Assuming 24 hours for email token expiration, replace with actual value if different
    const isTokenExpired = moment(manager.confirmation_sent_at).add(emailExpiredInHours, 'hours').isBefore(moment());
    if (isTokenExpired) {
      throw new BadRequestException('Confirmation token is expired');
    }

    manager.confirmed_at = new Date();
    await this.managersRepository.save(manager);

    return { user: manager };
  }
}
