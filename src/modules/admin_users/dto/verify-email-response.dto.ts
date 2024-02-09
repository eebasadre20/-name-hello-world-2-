import { AdminUser } from '@entities/admin_users';

export class VerifyEmailResponse {
  id: number;
  email: string;
  created_at: Date;
  updated_at: Date;
  // Add any other relevant fields from the AdminUser entity

  constructor(user: AdminUser) {
    this.id = user.id;
    this.email = user.email;
    this.created_at = user.created_at;
    this.updated_at = user.updated_at;
    // Initialize other fields here
  }
}
