import { IsString, Matches } from 'class-validator';

export class ConfirmEmailRequest {
  @IsString()
  @Matches(/^[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/, { message: 'Invalid token format' })
  token: string;
}

export class ConfirmEmailResponse {
  user: any; // Assuming Manager is imported or defined elsewhere in the actual codebase

  constructor(manager: any) {
    this.user = {
      id: manager.id,
      created_at: manager.created_at,
      updated_at: manager.updated_at,
      // Include other necessary fields from the Manager model
    };
  }
}
