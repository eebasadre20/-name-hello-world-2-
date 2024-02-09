import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { LogoutManagerRequest } from './dto/logout-manager.dto'; // Added from new code
import { sendConfirmationEmail } from './utils/email.util';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken'; // Keep from existing code
import { randomBytes } from 'crypto';

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

    const confirmationToken = randomBytes(32).toString('hex');

    const hashedPassword = await bcrypt.hash(password, 10);

    const manager = this.managersRepository.create({
      email,
      password: hashedPassword,
      confirmation_token: confirmationToken,
      confirmed_at: null,
    });

    await this.managersRepository.save(manager);

    const confirmationUrl = `http://yourfrontend.com/confirm?confirmation_token=${confirmationToken}`;
    await sendConfirmationEmail(email, confirmationToken, confirmationUrl);

    return { user: manager };
  }

  async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    const { token, password } = request;

    const manager = await this.managersRepository.findOne({ where: { reset_password_token: token } });
    if (!manager) {
      throw new BadRequestException('Token is not valid');
    }

    const resetPasswordExpireInHours = 1;
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

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    const { email, password } = request;
    const manager = await this.managersRepository.findOne({ where: { email } });

    if (!manager || !(await bcrypt.compare(password, manager.password))) {
      manager.failed_attempts += 1;
      if (manager.failed_attempts >= 5) {
        manager.locked_at = new Date();
        manager.failed_attempts = 0;
        await this.managersRepository.save(manager);
        throw new BadRequestException('User is locked');
      }
      await this.managersRepository.save(manager);
      throw new BadRequestException('Email or password is not valid');
    }

    if (!manager.confirmed_at) {
      throw new BadRequestException('User is not confirmed');
    }

    if (manager.locked_at) {
      const unlockInHours = 24;
      const lockedTime = new Date(manager.locked_at).getTime();
      const currentTime = new Date().getTime();
      if (currentTime - lockedTime < unlockInHours * 60 * 60 * 1000) {
        throw new BadRequestException('User is locked');
      }
    }

    manager.failed_attempts = 0;
    await this.managersRepository.save(manager);

    const accessToken = jwt.sign({ id: manager.id, email: manager.email }, 'secret', { expiresIn: '24h' });
    const refreshToken = jwt.sign({ id: manager.id, email: manager.email }, 'refreshSecret', { expiresIn: '48h' });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: 86400,
      token_type: 'Bearer',
      scope: 'managers',
      created_at: new Date().toISOString(),
      refresh_token_expires_in: 172800,
    };
  }

  async logoutManager(request: LogoutManagerRequest): Promise<void> {
    // Implementation depends on the project setup, this is a placeholder
  }
}
