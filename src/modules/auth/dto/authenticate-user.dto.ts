import { IsNotEmpty, IsEmail, IsString, IsBoolean, IsOptional } from 'class-validator';

export class AuthenticateUserRequest {
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;

  @IsBoolean()
  @IsOptional()
  rememberMe?: boolean;
}

export class AuthenticationResponse {
  token: string;
  user: any; // Changed from UserProfile to any since UserProfile is not defined in the provided code.

  constructor(token: string, user: any) { // Changed from UserProfile to any since UserProfile is not defined in the provided code.
    this.token = token;
    this.user = user;
  }
}
