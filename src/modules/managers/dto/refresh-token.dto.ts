import { IsString, IsNotEmpty, IsOptional } from 'class-validator';

export class RefreshTokenRequest {
  @IsString()
  @IsNotEmpty()
  refresh_token: string;

  @IsString()
  @IsNotEmpty()
  scope: string;

  // Combining new and existing code by making client_id and client_secret optional
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
  expires_in: number;

  @IsString()
  @IsNotEmpty()
  token_type: string;

  @IsString()
  @IsNotEmpty()
  scope: string;

  @IsNotEmpty()
  created_at: string;

  @IsNotEmpty()
  refresh_token_expires_in: number;
}
