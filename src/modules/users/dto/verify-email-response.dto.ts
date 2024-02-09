import { IsString } from 'class-validator';
import { User } from '@entities/user'; // Assuming the User entity is exported from this path

export type VerifyEmailResponseStatus = 'success' | 'failure';

export class VerifyEmailResponseDto {
  @IsString()
  status: VerifyEmailResponseStatus;

  @IsString()
  message: string;

  user: User; // Added field to match the requirement
}
