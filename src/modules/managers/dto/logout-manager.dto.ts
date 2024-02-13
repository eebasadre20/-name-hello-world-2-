import { IsString, IsIn } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  token: string;

  @IsIn(['access_token', 'refresh_token'])
  token_type_hint: string;
}
