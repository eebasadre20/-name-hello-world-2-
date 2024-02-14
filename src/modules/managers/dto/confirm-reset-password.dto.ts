import { IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';

export class ConfirmResetPasswordRequest {
  @IsString()
  @IsNotEmpty()
  token: string; // Updated to match the requirement

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, { message: 'Password is invalid' })
  password: string;
}

export class ConfirmResetPasswordResponse {
  message?: string; // Made optional to match the requirement

  constructor(message?: string) {
    this.message = message;
  }
}
