import { IsNotEmpty, IsString } from 'class-validator';

export class ConfirmResetPasswordRequest {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

export class ConfirmResetPasswordResponse {
  message: string;
}
