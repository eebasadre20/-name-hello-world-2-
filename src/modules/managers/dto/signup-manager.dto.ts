
import { IsEmail, IsString, IsNotEmpty } from 'class-validator';
import { IsPassword } from '../../../shared/validators/is-password.validator';
import { IsEqualTo } from '../../../shared/validators/is-equal-to.validator';
import { Manager } from '../../entities/managers'; // Import the Manager entity without .ts extension

export class SignupManagerRequest {
  @IsEmail({}, { message: 'Email is invalid' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsPassword({ message: 'Password is invalid' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;

  @IsString({ message: 'Password confirmation must be a string' })
  @IsEqualTo('password', { message: 'Password confirmation does not match' })
  @IsNotEmpty({ message: 'Password confirmation is required' })
  password_confirmation: string;
}

export class SignupManagerResponse {
  user: Manager; // The user field will contain the manager's data after successful signup
}
