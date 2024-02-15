 { Injectable } from '@nestjs/common';
import { EmailService } from '../../../shared/email/email.service'; // Changed from MailerService to EmailService
// Removed unused import MailerService

@Injectable()
export class EmailUtil {
  constructor(private readonly emailService: EmailService) {} // Changed from mailerService to emailService

  async sendConfirmationEmail(email: string, token: string): Promise<void> {
    const confirmationUrl = `${process.env.FRONTEND_URL}/confirm?confirmation_token=${token}`; // Use environment variable for frontend URL
    try {
      await this.emailService.sendMail({ // Changed from mailerService to emailService
        to: email,
        subject: 'Confirm your Email',
        template: 'email-confirmation', // Corrected path to the email template
        context: {
          email: email,
          url: `${process.env.FRONTEND_URL}/confirm`, // Use environment variable for frontend URL
          token: token,
          link: confirmationUrl, // Added 'link' to match the requirement
        },
      });
    } catch (error) {
      console.error('Error sending confirmation email', error); // Error handling
      throw new Error('Error sending confirmation email');
    } // Fixed missing closing bracket
  }

  async sendPasswordResetEmail(email: string, token: string, name: string = "User"): Promise<void> {
    const passwordResetUrl = `${process.env.FRONTEND_URL}/reset-password?reset_token=${token}`; // Use environment variable for frontend URL
    try {
      await this.emailService.sendMail({ // Changed from mailerService to emailService
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
