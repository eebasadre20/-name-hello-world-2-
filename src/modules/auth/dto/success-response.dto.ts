import { IsNumber, IsString } from 'class-validator';

export class SuccessResponseDto {
  @IsNumber()
  userId: number;

  @IsString()
  email: string;

  @IsString()
  fullName: string;

  @IsString()
  token: string | null;
}
