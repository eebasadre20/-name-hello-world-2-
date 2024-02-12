import { IsString } from 'class-validator';

export class ConfirmEmailRequest {
  @IsString()
  token: string; // No change needed, already matches the requirement
}

export class ConfirmEmailResponse {
  user: any; // Assuming Manager is imported or defined elsewhere in the actual codebase

  constructor(manager: any) { // Changed Manager to any to match the current code until Manager model is defined
    this.user = {
      id: manager.id,
      created_at: manager.created_at,
      updated_at: manager.updated_at,
      // Include other necessary fields from the Manager model
    };
  }
}
