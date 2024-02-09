import { IsEmail, IsString, MinLength, MaxLength, Matches } from 'class-validator';
import { AdminUser } from '@entities/admin_users';

export class RegisterAdminUserRequest {
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(20, { message: 'Password must not exceed 20 characters' })
  @Matches(new RegExp('Password_Regex_From_Controller'), { message: 'Password does not meet complexity requirements' })
  password: string;
}

export class RegisterAdminUserResponse {
  admin_users: { id: number };
  
  constructor(newUser: AdminUser) {
    this.admin_users = { id: newUser.id };
  }
}
