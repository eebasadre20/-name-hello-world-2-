import { Body, Controller, Post, HttpException, HttpStatus } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ConfirmEmailRequest } from './dto/confirm-email.dto'; // Assuming the DTO exists
import { ManagersService } from './managers.service'; // Assuming the service exists and is correctly implemented

@Controller('/api/managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/confirm-email')
  async confirmEmail(@Body() request: ConfirmEmailRequest) {
    if (!request.confirmation_token) {
      throw new HttpException('confirmation_token is required', HttpStatus.BAD_REQUEST);
    }
    const result = await this.managersService.confirmEmail(request.confirmation_token);
    return result; // Assuming the service method returns the appropriate response
  }

  // ... other methods remain unchanged
}
