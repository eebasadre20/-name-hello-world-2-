import { IsString, IsIn, IsNotEmpty } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @IsIn(['access_token', 'refresh_token'])
  @IsNotEmpty()
  token_type_hint: string;
}

export class LogoutManagerResponse {
  // Since the requirement specifies only sending status 200 without mentioning a response body,
  // this class is currently empty and can be extended in the future if needed.
}
