
import { IsEmail, IsString, IsNotEmpty, MinLength, Matches } from 'class-validator';

export class SignupManagerDto {
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/, { message: 'Password does not meet complexity requirements' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}

export class SignupManagerResponse {
  manager: { id: number }; // The response will contain the primary key of the manager's data after successful signup
}
