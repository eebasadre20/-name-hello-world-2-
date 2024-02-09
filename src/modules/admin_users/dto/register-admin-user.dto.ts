import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';
import { AdminUser } from '@entities/admin_users';

export class RegisterAdminUserRequest {
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(20, { message: 'Password must not exceed 20 characters' })
  password: string;
}

export class RegisterAdminUserResponse {
  user: AdminUser;
}
