
import { IsString, Matches, IsNotEmpty } from 'class-validator';
import { Manager } from '../../entities/managers'; // This import is correct and should remain unchanged

export class ConfirmEmailRequest {
  @IsNotEmpty({ message: 'confirmation_token is required' })
  @IsString()
  @Matches(/^[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/, { message: 'Invalid token format' })
  token: string;
}

export class ConfirmEmailResponse {
  user: Manager; // The type is correct as per the ERD

  constructor(manager: Manager) {
    this.user = manager;
  }
}
