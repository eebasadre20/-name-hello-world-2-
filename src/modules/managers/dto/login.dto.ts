import { IsEmail, IsString, MinLength, MaxLength, IsOptional } from 'class-validator';

export class LoginRequest {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  @MaxLength(50)
  password: string;

  @IsString()
  @IsOptional()
  client_id?: string;

  @IsString()
  @IsOptional()
  client_secret?: string;

  @IsString()
  @IsOptional()
  scope?: string;
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
