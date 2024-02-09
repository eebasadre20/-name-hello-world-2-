import { Injectable } from '@nestjs/common';
import { EmailService } from 'src/services/email.service'; // Assuming EmailService is correctly located here

@Injectable()
export class EmailUtil {
  constructor(private readonly emailService: EmailService) {}

  async sendConfirmationEmail(email: string, token: string): Promise<void> {
    try {
      const frontendUrl = 'https://yourfrontend.com/confirm'; // Replace with your actual frontend URL
      const confirmationUrl = `${frontendUrl}?confirmation_token=${token}`;

      const emailTemplate = 'email_confirmation'; // Assuming this is the correct template identifier
      const emailBody = {
        to: email,
        subject: 'Confirm Your Email',
        template: emailTemplate,
        context: {
          email: email,
          url: confirmationUrl,
          token: token,
        },
      };

      await this.emailService.sendMail(emailBody);
    } catch (error) {
      console.error('Failed to send confirmation email', error);
      throw new Error('Email sending failed');
    }
  }

  async sendPasswordResetEmail(email: string, token: string, userName: string): Promise<void> {
    try {
      const frontendUrl = 'https://yourfrontend.com/reset-password'; // Replace with your actual frontend URL for password reset
      const passwordResetUrl = `${frontendUrl}?token=${token}`;

      const emailTemplate = 'email_reset_password'; // Assuming this is the correct template identifier
      const emailBody = {
        to: email,
        subject: 'Reset Your Password',
        template: emailTemplate,
        context: {
          name: userName,
          url: passwordResetUrl,
          token: token,
        },
      };

      await this.emailService.sendMail(emailBody);
    } catch (error) {
      console.error('Failed to send password reset email', error);
      throw new Error('Email sending failed');
    }
  }
}
