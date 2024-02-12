import { IsString } from 'class-validator';

export class ConfirmEmailRequest {
  @IsString()
  token: string; // Updated field name to match the requirement
}

export class ConfirmEmailResponse {
  user: Manager; // Assuming Manager is imported or defined elsewhere in the actual codebase

  constructor(manager: Manager) {
    this.user = {
      id: manager.id,
      created_at: manager.created_at,
      updated_at: manager.updated_at,
      // Include other necessary fields from the Manager model
    };
  }
}
