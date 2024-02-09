import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class AuthenticateUserRequest {
  @IsEmail({}, { message: 'Invalid email format.' })
  @IsNotEmpty({ message: 'Email is required.' })
  email: string;

  @IsString({ message: 'Password must be a string.' })
  @MinLength(8, { message: 'Password must be at least 8 characters long.' })
  @IsNotEmpty({ message: 'Password is required.' })
  password: string;

  rememberMe?: boolean;
}
