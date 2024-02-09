import { IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';

export class ConfirmResetPasswordRequest {
  @IsString()
  @IsNotEmpty()
  reset_token: string; // Changed from 'token' to 'reset_token' to match the controller's expected field

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, { message: 'Password is invalid' })
  password: string;

  @IsString()
  @IsNotEmpty()
  password_confirmation: string; // Added this field to match the controller's expected fields
}

export class ConfirmResetPasswordResponse {
  message: string;
}
