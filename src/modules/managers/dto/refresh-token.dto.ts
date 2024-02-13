import { IsString, IsNotEmpty } from 'class-validator';

export class RefreshTokenRequest {
  @IsString()
  @IsNotEmpty()
  refresh_token: string;

  @IsString()
  @IsNotEmpty()
  scope: string;

  @IsString()
  @IsNotEmpty()
  client_id: string; // Ensured this field is included as it's used in the controller

  @IsString()
  @IsNotEmpty()
  client_secret: string; // Ensured this field is included as it's used in the controller
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

  @IsNumber()
  @IsNotEmpty()
  expires_in: number;

  @IsString()
  @IsNotEmpty()
  token_type: string;

  @IsString()
  @IsNotEmpty()
  scope: string;

  @IsISO8601()
  @IsNotEmpty()
  created_at: string;

  @IsNumber()
  @IsNotEmpty()
  refresh_token_expires_in: number;
}
