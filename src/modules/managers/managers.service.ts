import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { comparePassword } from './utils/password.util';
import { generateAccessToken, generateRefreshToken } from './utils/token.util';

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  // Other service methods...

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    const { email, password } = request;

    const manager = await this.managersRepository.findOne({ where: { email } });

    if (!manager) {
      throw new BadRequestException('Email or password is not valid');
    }

    const isPasswordValid = await comparePassword(password, manager.password);
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
      const unlockInHours = 24; // Assuming unlock_in_hours is 24
      const lockedTime = new Date(manager.locked_at).getTime();
      const currentTime = new Date().getTime();
      if (currentTime - lockedTime < unlockInHours * 60 * 60 * 1000) {
        throw new BadRequestException('User is locked');
      } else {
        manager.locked_at = null; // Reset locked_at if the lock period has expired
        await this.managersRepository.save(manager);
      }
    }

    manager.failed_attempts = 0;
    await this.managersRepository.save(manager);

    const accessToken = generateAccessToken({ id: manager.id, email: manager.email }, '24h');
    const refreshToken = generateRefreshToken({ id: manager.id, email: manager.email }, '48h'); // Assuming remember_in_hours is 48

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

  // ... other service methods
}
