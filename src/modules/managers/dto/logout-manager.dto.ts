import { IsString, IsNotEmpty, IsIn } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @IsNotEmpty()
  @IsIn(['access_token', 'refresh_token'])
  token_type_hint: string;
}

export class LogoutManagerResponse {
  // Since the requirement specifies only sending status 200 without mentioning a response body,
  // this class is currently empty and can be extended in the future if needed.
  // For demonstration, let's add an optional message field that could be used for debugging or confirmation.
  message?: string;
}
