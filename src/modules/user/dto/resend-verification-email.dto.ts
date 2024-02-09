import { IsEmail, IsNotEmpty } from 'class-validator';

export class ResendVerificationEmailRequest {
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
