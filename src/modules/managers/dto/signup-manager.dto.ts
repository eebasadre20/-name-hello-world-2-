
import { IsEmail, IsString, IsNotEmpty, MinLength, Matches } from 'class-validator';
import { IsPassword } from '../../../shared/validators/is-password.validator';
import { IsEqualTo } from '../../../shared/validators/is-equal-to.validator';
import { Manager } from '../../entities/managers'; // Import the Manager entity without .ts extension

export class SignupManagerRequest {
  @IsNotEmpty({ message: 'First name is required' })
  @IsString({ message: 'First name must be a string' })
  firstName: string;

  @IsNotEmpty({ message: 'Last name is required' })
  @IsString({ message: 'Last name must be a string' })
  lastName: string;

  @IsEmail({}, { message: 'Email is invalid' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @MinLength(8, { message: 'Password must be at least 8 characters long' }) // Assuming password_min_length is 8
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/, { message: 'Password does not meet complexity requirements' }) // Assuming password_regex is for a password with at least one uppercase, one lowercase, and one number
  @IsPassword({ message: 'Password is invalid' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;

  @IsString({ message: 'Password confirmation must be a string' })
  @IsEqualTo('password', { message: 'Password confirmation does not match' })
  @IsNotEmpty({ message: 'Password confirmation is required' })
  password_confirmation: string;
}

export class SignupManagerResponse {
  manager: { id: number }; // The response will contain the primary key of the manager's data after successful signup
}
