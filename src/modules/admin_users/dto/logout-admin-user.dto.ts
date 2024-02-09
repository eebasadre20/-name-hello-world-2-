import { IsString, IsIn } from 'class-validator';

export class LogoutAdminUserRequest {
  @IsString()
  token: string;

  @IsString()
  @IsIn(['access_token', 'refresh_token'], { message: 'token_type_hint must be either access_token or refresh_token' })
  token_type_hint: string;
}

export class LogoutAdminUserResponse {
  status: 200;
}
