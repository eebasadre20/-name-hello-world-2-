import { IsString, IsNotEmpty, IsIn } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @IsNotEmpty()
  @IsIn(['access_token', 'refresh_token'], { message: 'Invalid token type hint' }) // Added custom message for validation
  token_type_hint: string;
}

export class LogoutManagerResponse {}
