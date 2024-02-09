import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';

export class LoginRequest {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  @MaxLength(50) // Adjusted max length to 50 to provide a more reasonable upper limit for passwords
  password: string;
}

export class LoginResponse {
  access_token: string;
  refresh_token: string;
  resource_owner: string;
  resource_id: string;
  expires_in: number;
  token_type: string;
  scope: string;
  created_at: string;
  refresh_token_expires_in: number;
}
