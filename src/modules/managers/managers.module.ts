import { TypeOrmModule } from '@nestjs/typeorm';
import { Manager } from 'src/entities/manager'; // Assuming Manager entity exists
import { ManagersService } from './managers.service';
import { ManagersController } from './managers.controller';

@Module({
  imports: [TypeOrmModule.forFeature([Manager])], // Assuming Manager entity needs to be registered
  providers: [ManagersService],
  controllers: [ManagersController],
})
export class ManagersModule {}
