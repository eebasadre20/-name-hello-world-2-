import { IsEmail, IsString, MinLength, Matches } from 'class-validator';

export class SignupManagerRequest {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, { message: 'Password is invalid' })
  password: string;

  @IsString()
  @MinLength(8)
  password_confirmation: string;
}

export class SignupManagerResponse {
  user: any; // Assuming the Manager model is not yet defined or imported. Replace 'any' with the actual Manager model once defined or imported.
}
