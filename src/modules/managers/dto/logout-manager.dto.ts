import { IsString, IsNotEmpty, IsIn } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;

  // Removed the token_type_hint field as it is not used in the controller code
}

export class LogoutManagerResponse {
  // Define any additional response properties here if needed in the future
}
