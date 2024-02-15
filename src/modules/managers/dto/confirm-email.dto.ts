import { IsString, Matches } from 'class-validator';
import { Manager } from '../../entities/managers'; // Correct relative import of the Manager entity

export class ConfirmEmailRequest {
  @IsString()
  @Matches(/^[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/, { message: 'Invalid token format' })
  token: string;
}

export class ConfirmEmailResponse {
  user: Manager;

  constructor(manager: Manager) {
    this.user = manager;
  }
}
