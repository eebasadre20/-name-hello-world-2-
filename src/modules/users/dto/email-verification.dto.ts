import { IsDate, IsInt, IsString } from 'class-validator';

export class EmailVerificationToken {
  @IsInt()
  user_id: number;

  @IsString()
  token: string;

  @IsDate()
  created_at: Date;

  @IsDate()
  expires_at: Date;
}
