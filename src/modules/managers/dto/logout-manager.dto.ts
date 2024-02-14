import { IsString, IsNotEmpty } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;
}

// Removed the LogoutManagerResponse class as it is not used in the controller code and does not contain any properties.
