import { Body, Controller, Post, BadRequestException } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ManagersService } from './managers.service';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';

@Controller('/managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/confirm-email')
  async confirmEmail(@Body() body: { confirmation_token: string }): Promise<ConfirmEmailResponse> {
    if (!body.confirmation_token) {
      throw new BadRequestException('confirmation_token is required');
    }
    const request: ConfirmEmailRequest = { token: body.confirmation_token };
    return this.managersService.confirmEmail(request);
  }

  // ... other controller methods
}
