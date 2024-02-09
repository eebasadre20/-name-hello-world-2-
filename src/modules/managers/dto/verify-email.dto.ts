import { IsString } from 'class-validator';

export class VerifyEmailRequest {
  @IsString()
  token: string;
}

export class VerifyEmailResponse {
  user: any; // Replace 'any' with the actual Manager model once defined or imported.
}
