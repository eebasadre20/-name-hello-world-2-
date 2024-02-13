import { IsEmail, IsString, MinLength, Matches, IsNotEmpty } from 'class-validator';
import { Manager } from '@entities/managers'; // Assuming Manager entity is defined in the given path

export class SignupManagerRequest {
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, { message: 'Password must contain at least one letter and one number' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;

  @IsString({ message: 'Password confirmation is required' })
  @IsNotEmpty({ message: 'Password confirmation is required' })
  password_confirmation: string; // Added back the password_confirmation field as it is used in the controller for validation
}

export class SignupManagerResponse {
  user: Manager;
}
