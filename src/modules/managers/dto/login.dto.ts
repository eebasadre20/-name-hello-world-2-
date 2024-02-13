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
  expires_in: number = 86400; // 24 hours to seconds
  token_type: string = 'Bearer';
  scope: string;
  created_at: string;
  refresh_token_expires_in: number; // This will be calculated based on remember_in_hours

  constructor({access_token, refresh_token, resource_owner, resource_id, scope, created_at, remember_in_hours}: {access_token: string, refresh_token: string, resource_owner: string, resource_id: string, scope: string, created_at: string, remember_in_hours: number}) {
    this.access_token = access_token;
    this.refresh_token = refresh_token;
    this.resource_owner = resource_owner;
    this.resource_id = resource_id;
    this.scope = scope;
    this.created_at = created_at;
    this.refresh_token_expires_in = remember_in_hours * 3600; // to seconds
  }
}
