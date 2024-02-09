import { Injectable, BadRequestException } from '@nestjs/common';
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

  async verifyEmail({ token }: VerifyEmailRequest): Promise<VerifyEmailResponse> {
    const tokenRecord = await this.emailVerificationTokensRepository.findOne({
      where: { confirmation_token: token, confirmed_at: null },
    });

    if (!tokenRecord) {
      throw new BadRequestException('Confirmation token is not valid');
    }

    const emailExpiredInHours = {{email_expired_in}}; // Replace {{email_expired_in}} with actual value
    const expirationDate = new Date(tokenRecord.confirmation_sent_at);
    expirationDate.setHours(expirationDate.getHours() + emailExpiredInHours);

    if (new Date() > expirationDate) {
      throw new BadRequestException('Confirmation token is expired');
    }

    await this.usersRepository.update(tokenRecord.user_id, { confirmed_at: new Date() });

    const updatedUser = await this.usersRepository.findOne({
      where: { id: tokenRecord.user_id },
    });

    return { user: updatedUser };
  }

  // ... other methods ...
}
