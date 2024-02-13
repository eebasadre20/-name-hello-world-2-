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

// Removed the LogoutManagerResponse class as it is not used in the controller code.
