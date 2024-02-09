import { IsString, MinLength, MaxLength, Matches } from 'class-validator';

export class ConfirmResetPasswordRequest {
  @IsString()
  reset_token: string; // Updated from 'token' to 'reset_token' to match the controller's requirement

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(20, { message: 'Password must not exceed 20 characters' }) // Kept MaxLength as 20 to align with the existing DTO structure
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, {
    message: 'Password must contain at least one letter and one number',
  }) // Kept the regex as is because it matches the controller's requirement for password complexity
  password: string;

  @IsString()
  password_confirmation: string; // Added to match the controller's requirement
}

export class SuccessResponse {
  message: string;
}
