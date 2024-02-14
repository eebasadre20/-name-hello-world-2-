import { IsString, IsNotEmpty, IsIn } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;

  // Removed @IsIn(['access_token', 'refresh_token']) as it is not used in the controller
  @IsString()
  @IsNotEmpty()
  token_type_hint: string;
}

// Removed LogoutManagerResponse as it is not used in the controller
