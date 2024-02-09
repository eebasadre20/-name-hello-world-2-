import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

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

  async sendPasswordResetEmail(email: string, token: string, name: string): Promise<void> {
    const passwordResetUrl = `http://yourfrontend.com/reset-password?token=${token}`;
    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Password Reset Request',
        template: './email_reset_password', // path to the email template
        context: {
          name: name,
          url: passwordResetUrl,
          token: token,
          link: passwordResetUrl, // Assuming 'link' is the same as 'url' for simplicity
        },
      });
    } catch (error) {
      console.error('Error sending password reset email', error);
      throw new Error('Error sending password reset email');
    }
  }
}
