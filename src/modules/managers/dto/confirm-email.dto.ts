import { IsString, Matches } from 'class-validator';
import { Manager } from 'src/entities/managers'; // Assuming the path to the Manager entity

export class ConfirmEmailRequest {
  @IsString()
  @Matches(/^[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/, { message: 'Invalid token format' })
  token: string;
}

export class ConfirmEmailResponse {
  user: {
    id: string;
    created_at: Date;
    updated_at: Date;
    // Include other necessary fields from the Manager model
  };

  constructor(manager: Manager) {
    this.user = {
      id: manager.id,
      created_at: manager.created_at,
      updated_at: manager.updated_at,
      // Map other necessary fields from the Manager model here
    };
  }
}
