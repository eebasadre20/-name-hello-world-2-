import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Manager } from 'src/entities/managers';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';
import * as bcrypt from 'bcrypt';
import * as moment from 'moment';
import { randomBytes } from 'crypto';
import { jwt } from 'jsonwebtoken'; // Assuming jwt is used for token generation

@Injectable()
export class ManagersService {
  constructor(
    @InjectRepository(Manager)
    private managersRepository: Repository<Manager>,
  ) {}

  // ... other service methods

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

  // Placeholder for the blacklistToken function. Replace with your actual implementation.
  private async blacklistToken(token: string, type: string): Promise<void> {
    // Logic to blacklist the token
  }

  // ... other service methods
}
