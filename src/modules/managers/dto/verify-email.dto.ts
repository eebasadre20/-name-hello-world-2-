import { IsString, IsNotEmpty, Matches } from 'class-validator';

export class VerifyEmailRequest {
  @IsString()
  @IsNotEmpty()
  @Matches(/^[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/, { message: 'Invalid token format' })
  token: string;
}

export class VerifyEmailResponse {
  user: any; // Replace 'any' with the actual Manager model once defined or imported.
}
