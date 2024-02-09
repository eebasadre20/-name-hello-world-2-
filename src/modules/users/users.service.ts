import { Injectable, BadRequestException, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/entities/users';
import { EmailVerificationToken } from 'src/entities/email_verification_tokens';
import { PasswordResetToken } from 'src/entities/password_reset_tokens';
import { RegisterUserRequest, RegistrationResponse } from './dto/register-user.dto';
import { VerifyEmailRequestDto } from './dto/verify-email-request.dto';
import { VerifyEmailResponseDto } from './dto/verify-email-response.dto'; // Import the response DTO
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { MessageResponseDto } from './dto/message-response.dto';
import { hashPassword } from './utils/password.util';
import { sendVerificationEmail, sendPasswordResetEmail } from './utils/email.util';
import { validateRegistrationFields } from './utils/validation.util';
import { randomBytes } from 'crypto';
import { addMinutes } from 'date-fns';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    @InjectRepository(EmailVerificationToken)
    private emailVerificationTokensRepository: Repository<EmailVerificationToken>,
    @InjectRepository(PasswordResetToken)
    private passwordResetTokensRepository: Repository<PasswordResetToken>,
    // ... other injections ...
  ) {}

  // ... other constructors and methods ...

  async registerNewUser(registerUserDto: RegisterUserRequest): Promise<RegistrationResponse> {
    validateRegistrationFields(registerUserDto);

    const { email, password, full_name } = registerUserDto;

    const existingUser = await this.usersRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new ConflictException('Email is already in use.');
    }

    const hashedPassword = await hashPassword(password);
    const newUser = this.usersRepository.create({
      email,
      password_hash: hashedPassword,
      full_name,
      terms_of_service_accepted: true,
      privacy_policy_accepted: true,
      email_verified: false,
    });

    await this.usersRepository.save(newUser);

    const verificationToken = randomBytes(32).toString('hex');
    const expiresAt = addMinutes(new Date(), 60); // Token expires in 60 minutes

    const emailVerificationToken = this.emailVerificationTokensRepository.create({
      token: verificationToken,
      user_id: newUser.id,
      expires_at: expiresAt,
    });

    await this.emailVerificationTokensRepository.save(emailVerificationToken);

    await sendVerificationEmail(email, verificationToken);

    return {
      message: `User has been registered and a verification email has been sent to ${email}.`,
    };
  }

  async verifyEmail(dto: VerifyEmailRequestDto): Promise<VerifyEmailResponseDto> {
    if (!dto.token) {
      throw new BadRequestException('Token must not be empty.');
    }

    const emailVerificationToken = await this.emailVerificationTokensRepository.findOne({
      where: { token: dto.token, confirmed_at: null },
    });

    if (!emailVerificationToken) {
      throw new BadRequestException('Confirmation token is not valid');
    }

    const tokenExpirationHours = 24; // Assuming {{email_expired_in}} is 24 hours
    const expirationDate = new Date(emailVerificationToken.confirmation_sent_at.getTime() + tokenExpirationHours * 60 * 60 * 1000);

    if (new Date() > expirationDate) {
      throw new BadRequestException('Confirmation token is expired');
    }

    await this.emailVerificationTokensRepository.update(emailVerificationToken.id, { confirmed_at: new Date() });

    const user = await this.usersRepository.findOne({ where: { id: emailVerificationToken.user_id } });

    if (!user) {
      throw new NotFoundException('User not found.');
    }

    return { user };
  }

  async issuePasswordResetToken(requestPasswordResetDto: RequestPasswordResetDto): Promise<MessageResponseDto> {
    const { email } = requestPasswordResetDto;
    if (!email) {
      throw new BadRequestException('Email must not be empty.');
    }

    const user = await this.usersRepository.findOne({ where: { email } });
    if (!user) {
      throw a NotFoundException('Email not registered.');
    }

    const token = randomBytes(32).toString('hex');
    const expiresAt = addMinutes(new Date(), 60); // Token expires in 60 minutes

    const passwordResetToken = this.passwordResetTokensRepository.create({
      token,
      user_id: user.id,
      expires_at: expiresAt,
    });

    await this.passwordResetTokensRepository.save(passwordResetToken);
    await sendPasswordResetEmail(email, token);

    return new MessageResponseDto({ message: 'Password reset instructions have been sent to your email.' });
  }

  // ... other methods ...
}
