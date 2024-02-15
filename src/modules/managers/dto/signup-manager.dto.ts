
import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';
import { IsPassword, IsEqualTo } from '../../../shared/validators/is-password.validator';

export class SignupManagerDto {
  @IsEmail({}, { message: 'Email is invalid' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsPassword({ pattern: '{{password_regex}}', message: 'Password is invalid' })
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength({{password_min_length}}, { message: 'Password must be at least {{password_min_length}} characters long' })
  password: string;

  @IsEqualTo('password', { message: 'Password confirmation does not match' })
  @IsNotEmpty({ message: 'Password confirmation is required' })
  password_confirmation: string;
}

export class SignupManagerResponse {
  manager: { id: number }; // The response will contain the primary key of the manager's data after successful signup
}
