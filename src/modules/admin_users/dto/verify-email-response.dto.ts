import { AdminUser } from '@entities/admin_users';

export class VerifyEmailResponse {
  user: AdminUser;

  constructor(user: AdminUser) {
    this.user = user;
  }
}
