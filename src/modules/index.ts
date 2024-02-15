import { HealthCheckModule } from './health-check/health-check.module';
import { UsersModule } from './users/users.module';
import { AdminUsersModule } from './admin_users/admin_users.module';
import { ManagersModule } from './managers/managers.module';

export default [HealthCheckModule, UsersModule, AdminUsersModule, ManagersModule];
