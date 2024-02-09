import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { sendConfirmationEmail } from './utils/email.util';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import * as jwt from 'jsonwebtoken'; // Assuming JWT is used for token generation

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  async signupManager(request: SignupManagerRequest): Promise<SignupManagerResponse> {
    const { email, password } = request;

    // Check if the email is already taken
    const existingManager = await this.managersRepository.findOne({ where: { email } });
    if (existingManager) {
      throw new BadRequestException('Email is already taken');
    }

    // Generate a confirmation token
    const confirmationToken = randomBytes(32).toString('hex');

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new manager record
    const manager = this.managersRepository.create({
      email,
      password: hashedPassword,
      confirmation_token: confirmationToken,
      confirmed_at: null,
    });

    await this.managersRepository.save(manager);

    // Send a confirmation email
    const confirmationUrl = `http://yourfrontend.com/confirm?confirmation_token=${confirmationToken}`;
    await sendConfirmationEmail(email, confirmationToken, confirmationUrl);

    return { user: manager };
  }

  async loginManager(request: LoginRequest): Promise<LoginResponse> {
    const { email, password } = request;
    const manager = await this.managersRepository.findOne({ where: { email } });

    if (!manager || !(await bcrypt.compare(password, manager.password))) {
      // Increase failed_attempts and check for lock
      manager.failed_attempts += 1;
      if (manager.failed_attempts >= 5) { // Assuming 5 is the maximum login attempts
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
      const unlockInHours = 24; // Assuming 24 hours to unlock
      const lockedTime = new Date(manager.locked_at).getTime();
      const currentTime = new Date().getTime();
      if (currentTime - lockedTime < unlockInHours * 60 * 60 * 1000) {
        throw new BadRequestException('User is locked');
      }
    }

    manager.failed_attempts = 0;
    await this.managersRepository.save(manager);

    // Generate tokens
    const accessToken = jwt.sign({ id: manager.id, email: manager.email }, 'secret', { expiresIn: '24h' }); // secret should be in environment variable
    const refreshToken = jwt.sign({ id: manager.id, email: manager.email }, 'refreshSecret', { expiresIn: '48h' }); // refreshSecret should be in environment variable, assuming 48 hours for refresh token

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      resource_owner: 'managers',
      resource_id: manager.id.toString(),
      expires_in: 86400,
      token_type: 'Bearer',
      scope: 'managers',
      created_at: new Date().toISOString(),
      refresh_token_expires_in: 172800, // 48 hours to seconds
    };
  }

  // ... rest of the service methods
}
