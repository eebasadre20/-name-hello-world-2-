import { IsString, IsNotEmpty, IsIn } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @IsNotEmpty()
  // Combining the new and existing validations for token_type_hint
  @IsIn(['access_token', 'refresh_token'])
  token_type_hint: string;
}
