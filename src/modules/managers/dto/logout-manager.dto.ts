
import { IsString, IsNotEmpty, IsIn } from 'class-validator';

export class LogoutManagerDto {
  @IsString()
  @IsNotEmpty({ message: 'token is required' })
  token: string;

  @IsString()
  @IsNotEmpty()
  @IsIn(['access_token', 'refresh_token'])
  token_type_hint: string;
}

export class LogoutManagerResponse {
  status: number = 200; // Updated to add a default value for status
}
