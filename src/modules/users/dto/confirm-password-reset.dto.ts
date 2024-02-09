import { IsString, IsNotEmpty, MinLength, MaxLength, Matches } from 'class-validator';

export class ConfirmPasswordResetRequest {
  @IsString()
  @IsNotEmpty({ message: 'Token must not be empty.' })
  token: string;

  @IsString()
  @IsNotEmpty({ message: 'New password must not be empty.' })
  @MinLength(8, { message: 'New password must be at least 8 characters long.' })
  @MaxLength(50, { message: 'New password must be at most 50 characters long.' })
  @Matches(/((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,50})/, {
    message: 'Password too weak',
  })
  new_password: string;

  @IsString()
  @IsNotEmpty({ message: 'Confirm new password must not be empty.' })
  confirm_new_password: string;
}

export class ConfirmPasswordResetResponse {
  @IsString()
  success: boolean;
  
  @IsString()
  message: string;

  constructor(success: boolean, message: string) {
    this.success = success;
    this.message = message;
  }
}
