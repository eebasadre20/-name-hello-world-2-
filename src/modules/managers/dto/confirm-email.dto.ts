
import { IsString, IsNotEmpty } from 'class-validator';
import { Manager } from '../../entities/managers'; // This import is correct and should remain unchanged

export class ConfirmEmailRequest {
  @IsNotEmpty({ message: 'confirmation_token is required' }) // Updated validation message
  @IsString()
  confirmation_token: string; // Renamed field to match the requirement
}

export class ConfirmEmailResponse {
  user: Manager; // The type is correct as per the ERD

  constructor(manager: Manager) {
    this.user = manager;
  }
}
