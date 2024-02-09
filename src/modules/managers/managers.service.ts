import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { sendConfirmationEmail } from './utils/email.util';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';

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

  // ... rest of the service methods
}
