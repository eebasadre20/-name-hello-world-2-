import { IsEmail, IsString } from 'class-validator';

export class ResendVerificationEmailRequest {
  @IsEmail({}, { message: 'Invalid email address.' })
  email: string;
}

export class ResendVerificationEmailResponse {
  @IsString()
  message: string;
}
