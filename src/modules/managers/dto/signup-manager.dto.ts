import { IsEmail, IsString, MinLength } from 'class-validator';

export class SignupManagerRequest {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;
}

export class SignupManagerResponse {
  user: Manager;
}
