import { Body, Controller, Post, BadRequestException } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ManagersService } from './managers.service';
import { LogoutManagerRequest } from './dto/logout-manager.dto';

@Controller('managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/logout')
  async logout(@Body() logoutManagerRequest: LogoutManagerRequest): Promise<void> {
    if (!logoutManagerRequest.token) {
      throw new BadRequestException('token is required');
    }
    await this.managersService.logoutManager(logoutManagerRequest);
  }

  // ... other controller methods
}
