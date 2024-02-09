import { IsNotEmpty, IsString, Matches } from 'class-validator';

export class ResetPasswordRequest {
  @IsNotEmpty()
  @IsString()
  token: string;

  @IsNotEmpty()
  @IsString()
  @Matches(/((?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,30})/, {
    message: 'password too weak',
  })
  password: string;

  @IsNotEmpty()
  @IsString()
  password_confirmation: string;
}

export class ResetPasswordResponse {
  @IsString()
  message: string;
}
