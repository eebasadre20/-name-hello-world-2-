import { IsString, MinLength, MaxLength, Matches } from 'class-validator';

export class ConfirmResetPasswordRequest {
  @IsString()
  token: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(20, { message: 'Password must not exceed 20 characters' })
  @Matches(/^(?=.*[a-zA-Z])(?=.*[0-9]).*$/, {
    message: 'Password must contain at least one letter and one number',
  })
  password: string;
}

export class SuccessResponse {
  message: string;
}
