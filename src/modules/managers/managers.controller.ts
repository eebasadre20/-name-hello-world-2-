import { Body, Controller, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ManagersService } from './managers.service';
import { LogoutManagerRequest } from './dto/logout-manager.dto';

@Controller('managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/logout')
  async logout(@Body() logoutManagerRequest: LogoutManagerRequest) {
    if (!logoutManagerRequest.token) {
      throw new BadRequestException('token is required');
    }
    return this.managersService.logoutManager(logoutManagerRequest);
  }

  // ... other existing controller methods
}
