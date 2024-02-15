import { IsString, IsNotEmpty, IsOptional } from 'class-validator';

export class RefreshTokenRequest {
  @IsString()
  @IsNotEmpty()
  refresh_token: string;

  @IsString()
  @IsNotEmpty()
  scope: string;

  @IsString()
  @IsOptional()
  client_id?: string;

  @IsString()
  @IsOptional()
  client_secret?: string;
}

export class RefreshTokenResponse {
  @IsString()
  @IsNotEmpty()
  access_token: string;

  @IsString()
  @IsNotEmpty()
  refresh_token: string;

  @IsString()
  @IsNotEmpty()
  resource_owner: string;

  @IsString()
  @IsNotEmpty()
  resource_id: string;

  @IsNotEmpty()
  expires_in: number = 86400; // 24 hours to seconds

  @IsString()
  @IsNotEmpty()
  token_type: string = 'Bearer';

  @IsString()
  @IsNotEmpty()
  scope: string;

  @IsNotEmpty()
  created_at: string;

  @IsNotEmpty()
  refresh_token_expires_in: number; // {{remember_in_hours}} to seconds will be set in service logic
}
