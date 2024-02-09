import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ResetPasswordRequest {
  @IsNotEmpty({ message: 'Token is required.' })
  @IsString()
  token: string;

  @IsNotEmpty({ message: 'Password is required.' })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long.' })
  password: string;

  @IsEmail({}, { message: 'Invalid email address.' })
  @IsNotEmpty({ message: 'Email is required.' })
  email: string;
}

export class ResetPasswordResponse {
  @IsString()
  message: string;
}
