import { IsString, IsNotEmpty } from 'class-validator';

export class VerifyEmailRequestDto {
  @IsString()
  @IsNotEmpty({ message: 'Token must not be empty.' })
  token: string;
}
