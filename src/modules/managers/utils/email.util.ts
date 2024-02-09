import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { Manager } from 'src/entities/managers';

@Injectable()
export class EmailUtil {
  constructor(private readonly mailerService: MailerService) {}

  async sendConfirmationEmail(email: string, token: string): Promise<void> {
    const confirmationUrl = `http://yourfrontend.com/confirm?confirmation_token=${token}`;
    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Confirm your Email',
        template: './email_confirmation', // path to the email template
        context: {
          email: email,
          url: confirmationUrl,
          token: token,
        },
      });
    } catch (error) {
      console.error('Error sending confirmation email', error);
      throw new Error('Error sending confirmation email');
    }
  }
}