
import { IsEmail, IsString, MinLength, Matches, IsNotEmpty, ValidateIf } from 'class-validator';

export class LoginRequest {
  @IsEmail()
  email: string;

  @ValidateIf(o => o.grant_type === 'password')
  @IsNotEmpty({ message: 'password is required' })
  @MinLength(8, { message: 'Password is invalid' })
  @Matches('{{password_regex}}', { message: 'Password is invalid' })
  password: string;

  @IsNotEmpty({ message: 'grant_type is required' })
  @IsString()
  grant_type: 'password' | 'refresh_token';

  @IsString()
  @IsNotEmpty({ message: 'client_id is required' })
  client_id: string;

  @IsString()
  @IsNotEmpty({ message: 'client_secret is required' })
  client_secret: string;

  @ValidateIf(o => o.grant_type === 'refresh_token')
  @IsNotEmpty({ message: 'refresh_token is required' })
  @IsString()
  refresh_token: string;

  @IsNotEmpty({ message: 'scope is required' })
  @IsString()
  scope: string;
}

export class LoginResponse {
  access_token: string;
  refresh_token: string;
  resource_owner: string = 'managers';
  resource_id: number;
  expires_in: number = 86400; // 24 hours to seconds
  token_type: string = 'Bearer';
  scope: string;
  created_at: number;
  refresh_token_expires_in: number | null;
}
