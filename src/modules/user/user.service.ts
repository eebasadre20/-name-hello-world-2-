import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/entities/users';
import { EmailVerificationToken } from 'src/entities/email_verification_tokens';
import { UpdateUserProfileRequest, UpdateUserProfileResponse } from './dto/update-user-profile.dto';
import { validateEmailFormat } from './utils/validation.util';
import { initiateEmailVerificationProcess } from './utils/email.util';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(EmailVerificationToken)
    private emailVerificationTokenRepository: Repository<EmailVerificationToken>,
    // ... other dependencies ...
  ) {}

  // ... other methods ...

  async updateUserProfile(request: UpdateUserProfileRequest): Promise<UpdateUserProfileResponse> {
    // Validate the email format
    if (!validateEmailFormat(request.email)) {
      throw new BadRequestException('Invalid email format');
    }

    // Check if the user ID exists
    const user = await this.userRepository.findOne({ where: { id: request.id } });
    if (!user) {
      throw new NotFoundException('Invalid user ID');
    }

    // Check if the new email is different from the current one and if it is already in use
    if (user.email !== request.email) {
      const emailInUse = await this.userRepository.findOne({ where: { email: request.email } });
      if (emailInUse) {
        throw new BadRequestException('Email is already registered');
      }

      // Update the user's email and set email_verified to false
      user.email = request.email;
      user.email_verified = false;
      initiateEmailVerificationProcess(user.id);
    }

    // Update the user's full name
    user.full_name = request.full_name;

    // Save the updated user profile
    await this.userRepository.save(user);

    return { message: 'User profile updated successfully' };
  }

  // ... rest of the service ...
}
