import { IsEmail, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class UpdateUserProfileRequest {
  @IsString()
  @IsNotEmpty()
  id: string;

  @IsEmail()
  @IsOptional()
  email?: string;

  @IsString()
  @IsNotEmpty()
  full_name: string;
}

export class UpdateUserProfileResponse {
  status: HttpStatus;
  message: string;
  user: any; // The type should be replaced with the actual User type/interface if available.
}
