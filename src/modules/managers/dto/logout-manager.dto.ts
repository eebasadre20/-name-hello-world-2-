import { IsString, IsNotEmpty, IsIn } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;

  // Removed the token_type_hint field as it's not used in the controller code provided
}
