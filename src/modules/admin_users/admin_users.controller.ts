import {
  Body,
  Controller,
  Post,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AdminUsersService } from './admin_users.service';
import { LogoutAdminUserRequest } from './dto/logout-admin-user.dto';

@Controller('admin_users')
@ApiTags('AdminUsers')
export class AdminUsersController {
  constructor(private readonly adminUsersService: AdminUsersService) {}

  @Post('logout')
  async logoutAdminUser(@Body() logoutAdminUserRequest: LogoutAdminUserRequest) {
    if (!logoutAdminUserRequest.token) {
      throw new BadRequestException('token is required');
    }
    return this.adminUsersService.logoutAdminUser(logoutAdminUserRequest);
  }

  // ... other existing controller methods
}
