import { IsString } from 'class-validator';

export class PasswordResetRequestResponse {
  @IsString()
  message: string;
}
