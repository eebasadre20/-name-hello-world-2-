import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AdminUser } from 'src/entities/admin_users';
import { RegisterAdminUserRequest, RegisterAdminUserResponse } from './dto/register-admin-user.dto';
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

    return { user: newUser }; // This line has been updated to match the requirement of returning a RegisterAdminUserResponse type.
  }

  // ... other methods
}
