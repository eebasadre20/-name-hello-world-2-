import { IsString, IsNotEmpty, MinLength, MaxLength, Matches } from 'class-validator';

export class ResetPasswordRequest {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(50)
  @Matches(/((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,50})/, {
    message: 'Password too weak',
  })
  password: string;

  @IsString()
  @IsNotEmpty()
  password_confirmation: string;
}

export class ResetPasswordResponse {
  @IsString()
  message: string;
}
