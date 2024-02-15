import { IsEmail, IsString, MinLength, Matches, IsNotEmpty } from 'class-validator';
// Assuming Manager entity is defined in the given path
import { Manager } from '@entities/managers'; 

export class SignupManagerRequest {
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, { message: 'Password must contain at least one letter and one number' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;

  @IsString({ message: 'Password confirmation must be a string' })
  @IsNotEmpty({ message: 'Password confirmation is required' })
  password_confirmation: string;
}

export class SignupManagerResponse {
  user: Manager;
}
