import { IsEmail, IsNotEmpty } from 'class-validator';

export class RequestPasswordResetRequest {
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;
}
