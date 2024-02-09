import { IsEmail, IsString, MinLength, MaxLength, Matches } from 'class-validator';
import { AdminUser } from '@entities/admin_users';

export class RegisterAdminUserRequest {
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(20, { message: 'Password must not exceed 20 characters' })
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, { message: 'Password does not meet complexity requirements' }) // Updated regex to match the controller's requirement
  password: string;
}

export class RegisterAdminUserResponse {
  admin_users: { id: number };
  
  constructor(newUser: AdminUser) {
    this.admin_users = { id: newUser.id };
  }
}
