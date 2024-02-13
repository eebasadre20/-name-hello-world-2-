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
