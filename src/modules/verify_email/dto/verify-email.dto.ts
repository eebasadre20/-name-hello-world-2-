import { IsString } from 'class-validator';

export class VerifyEmailRequest {
  @IsString()
  user_id: string;

  @IsString()
  token: string;
}

export class VerifyEmailResponse {
  @IsString()
  message: string;

  @IsString()
  next_steps?: string;
}
