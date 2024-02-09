import { IsString } from 'class-validator';

export class RefreshTokenRequest {
  @IsString()
  refresh_token: string;

  @IsString()
  scope: string;
}

export class RefreshTokenResponse {
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
