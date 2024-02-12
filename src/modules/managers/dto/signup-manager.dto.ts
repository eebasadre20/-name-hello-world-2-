import { IsEmail, IsString, MinLength, Matches } from 'class-validator';
import { Manager } from '@entities/managers'; // Assuming Manager entity is defined in the given path

export class SignupManagerRequest {
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, { message: 'Password is invalid' })
  password: string;
}

export class ManagerResponse {
  user: Manager;
}
