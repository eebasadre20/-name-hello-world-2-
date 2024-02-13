import { IsString, IsNotEmpty } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;
}

export class LogoutManagerResponse {
  message?: string;
}
