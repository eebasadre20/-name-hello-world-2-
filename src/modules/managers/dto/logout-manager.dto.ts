import { IsString, IsIn } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  token: string;

  // Removed the token_type_hint field as it is not used in the controller's logic
}
