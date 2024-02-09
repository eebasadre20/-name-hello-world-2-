import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AdminUser } from 'src/entities/admin_users';
import { RegisterAdminUserRequest, RegisterAdminUserResponse, ConfirmResetPasswordRequest, SuccessResponse } from './dto';
import * as bcrypt from 'bcrypt';
import { sendConfirmationEmail } from './utils/email.util';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AdminUsersService {
  constructor(
    @InjectRepository(AdminUser)
    private adminUsersRepository: Repository<AdminUser>,
  ) {}

  async signupWithEmail({ email, password }: RegisterAdminUserRequest): Promise<RegisterAdminUserResponse> {
    const existingUser = await this.adminUsersRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new BadRequestException('Email is already taken');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const confirmationToken = uuidv4();

    const newUser = this.adminUsersRepository.create({
      email,
      password: hashedPassword,
      confirmation_token: confirmationToken,
      confirmed_at: null,
    });

    await this.adminUsersRepository.save(newUser);

    const confirmationUrl = `http://frontend.url/confirm?confirmation_token=${confirmationToken}`;
    await sendConfirmationEmail(email, confirmationToken, confirmationUrl);

    return { user: newUser };
  }

  async confirmResetPassword({ token, password }: ConfirmResetPasswordRequest): Promise<SuccessResponse> {
    const user = await this.adminUsersRepository.findOne({ where: { reset_password_token: token } });
    if (!user) {
      throw new BadRequestException('Token is not valid');
    }

    const resetPasswordExpireInHours = 2; // Assuming 2 hours for password reset token expiration
    const expirationDate = new Date(user.reset_password_sent_at);
    expirationDate.setHours(expirationDate.getHours() + resetPasswordExpireInHours);

    if (new Date() > expirationDate) {
      throw new BadRequestException('Token is expired');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.reset_password_token = null;
    user.reset_password_sent_at = null;

    await this.adminUsersRepository.save(user);

    return { message: "Password reset successfully" };
  }

  // ... other methods
}
