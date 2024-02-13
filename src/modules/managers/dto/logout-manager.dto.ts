import { IsString, IsNotEmpty } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;
}

export class LogoutManagerResponse {
  // Since the requirement specifies only sending status 200 without mentioning a response body,
  // this class is currently empty and can be extended in the future if needed.
}
