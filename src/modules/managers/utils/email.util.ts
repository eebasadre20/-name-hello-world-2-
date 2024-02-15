
import { Injectable } from '@nestjs/common';
import { EmailService } from '../../../shared/email/email.service';
import { Manager } from '../../entities/managers.ts'; // Assuming the Manager entity exists

@Injectable()
export class EmailUtil {
  constructor(private readonly emailService: EmailService) {}

  async sendConfirmationEmail(email: string, token: string): Promise<void> {
    const confirmationUrl = `${process.env.FRONTEND_URL}/confirm?confirmation_token=${token}`;
    try {
      await this.emailService.sendMail({
        to: email,
        subject: 'Confirm your Email',
        template: 'email_confirmation', // Updated template name to match the requirement
        context: {
          email: email,
          url: `${process.env.FRONTEND_URL}/confirm`,
          token: token,
          link: confirmationUrl,
        },
      });
      // No changes required here as the existing code already matches the requirement
    } catch (error) {
      console.error('Error sending confirmation email', error);
      throw new Error('Error sending confirmation email');
    }
  }

  async sendPasswordResetEmail(email: string, token: string, name: string = "User"): Promise<void> {
    const passwordResetUrl = `${process.env.FRONTEND_URL}/reset-password?reset_token=${token}`;
    // No changes required in this function as it is not related to the requirement
    try {
      await this.emailService.sendMail({
        to: email,
        subject: 'Password Reset Request',
        template: './email_reset_password', // path to the email template
        context: {
          name: name,
          url: passwordResetUrl,
          token: token,
          link: passwordResetUrl, // Ensuring 'link' is also included for consistency with the requirement
        },
      });
    } catch (error) {
      console.error('Error sending password reset email', error);
    }
  }
}
