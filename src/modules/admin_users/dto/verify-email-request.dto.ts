import { IsString, IsNotEmpty } from 'class-validator';

export class VerifyEmailRequest {
  @IsString()
  @IsNotEmpty()
  token: string;
}
