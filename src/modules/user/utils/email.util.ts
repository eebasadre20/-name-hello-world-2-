import { Injectable } from '@nestjs/common';
import { User } from 'src/entities/users';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class EmailUtil {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async initiateEmailVerificationProcess(userId: string): Promise<void> {
    // Retrieve the user's new email address from the database
    const user = await this.userRepository.findOne(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Logic to send a verification email to the user's new email address
    // This should include generating a verification token, saving it to the database,
    // and sending an email with a link for the user to verify their new email address.
    // The actual implementation of this logic will depend on the specifics of the email sending service used.
    // For example:
    // const token = this.generateVerificationToken();
    // await this.saveVerificationToken(userId, token);
    // await this.sendVerificationEmail(user.email, token);

    // Placeholder for the actual email sending logic
    console.log(`Verification email sent to ${user.email}`);
  }

  // Placeholder for additional utility methods such as generateVerificationToken, saveVerificationToken, sendVerificationEmail, etc.
}
