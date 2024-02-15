import { Injectable } from '@nestjs/common';
import { EmailService } from '../../../shared/email/email.service';

@Injectable()
export class EmailUtil {
  constructor(private readonly emailService: EmailService) {}

  async sendConfirmationEmail(email: string, token: string): Promise<void> {
    const confirmationUrl = `${process.env.FRONTEND_URL}/confirm?confirmation_token=${token}`;
    try {
      await this.emailService.sendMail({
        to: email,
        subject: 'Confirm your Email',
        template: 'email_confirmation',
        context: {
          email: email,
          url: `${process.env.FRONTEND_URL}/confirm`,
          token: token,
          link: confirmationUrl,
        },
      });
    } catch (error) {
      console.error('Error sending confirmation email', error); // Log error for debugging
      throw new Error('Error sending confirmation email');
    }
  }

  async sendPasswordResetEmail(email: string, token: string, name: string = "User"): Promise<void> {
    const passwordResetUrl = `${process.env.FRONTEND_URL}/reset-password?reset_token=${token}`;
    try { // Try to send the password reset email
      await this.emailService.sendMail({
        to: email,
        subject: 'Password Reset Request',
        template: 'email_reset_password', // Removed the './' from the template path to match the new code
        context: {
          name: name,
          url: passwordResetUrl,
          token: token, // Include the token in the email context
          link: passwordResetUrl, // Ensuring 'link' is also included for consistency with the requirement
        },
      });
    } catch (error) {
      console.error('Error sending password reset email', error);
    }
  }
} // End of EmailUtil class
