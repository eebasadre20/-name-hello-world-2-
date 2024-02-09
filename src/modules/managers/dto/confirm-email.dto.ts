import { IsString } from 'class-validator';

export class ConfirmEmailRequest {
  @IsString()
  confirmation_token: string;
}
