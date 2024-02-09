import { TypeOrmModule } from '@nestjs/typeorm';
import { AdminUsersService } from './admin_users.service';
import { AdminUsersController } from './admin_users.controller';
import { AdminUser } from 'src/entities/admin_user';

@Module({
  imports: [TypeOrmModule.forFeature([AdminUser])],
  providers: [AdminUsersService],
  controllers: [AdminUsersController],
})
export class AdminUsersModule {}
