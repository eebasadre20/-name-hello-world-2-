import { IsString, IsNotEmpty } from 'class-validator';

export class LogoutManagerRequest {
  @IsString()
  @IsNotEmpty()
  token: string;

  // Removed token_type_hint as it's not used in the controller
  // Note: The new code and existing code for LogoutManagerRequest are effectively the same after the removal suggestion was applied.
}

export class LogoutManagerResponse {
  // Since the requirement specifies only sending status 200 without mentioning a response body,
  // this class is currently empty and can be extended in the future if needed.
  // Note: Keeping LogoutManagerResponse as it might be useful for future extensions.
}
