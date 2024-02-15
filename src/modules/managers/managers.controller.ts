import { Body, Controller, Post, BadRequestException } from '@nestjs/common';
import { ManagersService } from './managers.service';
import { ConfirmEmailRequest } from './dto/confirm-email.dto';

@Controller('/api/managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/confirm-email')
  async confirmEmail(@Body() body: { confirmation_token?: string }) {
    if (!body.confirmation_token) {
      throw new BadRequestException('confirmation_token is required');
    }
    const request: ConfirmEmailRequest = { token: body.confirmation_token };
    const response = await this.managersService.confirmEmail(request);
    return response;
  }

  // ... other existing controller methods
}
