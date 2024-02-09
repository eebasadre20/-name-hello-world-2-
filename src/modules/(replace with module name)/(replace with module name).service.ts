import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/entities/users';
import { EmailVerificationToken } from 'src/entities/email_verification_tokens';
import { VerifyEmailRequest, VerifyEmailResponse } from './dto/verify-email.dto';

@Injectable()
export class (ReplaceWithModuleName)Service {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    @InjectRepository(EmailVerificationToken)
    private emailVerificationTokensRepository: Repository<EmailVerificationToken>,
  ) {}

  async verifyEmail({ user_id, token }: VerifyEmailRequest): Promise<VerifyEmailResponse> {
    const tokenRecord = await this.emailVerificationTokensRepository.findOne({
      where: { user_id },
    });

    if (!tokenRecord || tokenRecord.token !== token || tokenRecord.expires_at < new Date()) {
      await this.emailVerificationTokensRepository.delete({ user_id });
      return {
        message: 'Verification failed. The token is invalid or has expired.',
        next_steps: 'Please request a new verification email.',
      };
    }

    await this.usersRepository.update(user_id, { email_verified: true });
    await this.emailVerificationTokensRepository.delete({ user_id });

    return {
      message: 'Email verification successful. You can now log in.',
    };
  }

  // ... other methods ...
}
