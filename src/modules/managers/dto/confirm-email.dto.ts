import { IsString } from 'class-validator';

export class ConfirmEmailRequest {
  @IsString()
  token: string; // Updated field name to match the requirement
}
