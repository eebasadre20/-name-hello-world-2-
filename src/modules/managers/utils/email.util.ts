import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
// Removed unused import

@Injectable()
export class EmailUtil {
  constructor(private readonly mailerService: MailerService) {}

  async sendConfirmationEmail(email: string, token: string): Promise<void> { // Corrected method signature
    const confirmationUrl = `http://yourfrontend.com/confirm?confirmation_token=${token}`;
    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Confirm your Email',
        template: 'email-confirmation', // Corrected path to the email template
        context: {
          email: email,
          url: confirmationUrl,
          token: token,
          link: confirmationUrl, // Added 'link' to match the requirement
        },
    } catch (error) { // Assuming error handling is done through console.error
    } catch (error) {
      console.error('Error sending confirmation email', error); // Error handling
      throw new Error('Error sending confirmation email');
    }
  }

  async sendPasswordResetEmail(email: string, token: string, name: string = "User"): Promise<void> {
    const passwordResetUrl = `http://yourfrontend.com/reset-password?reset_token=${token}`;
    try {
      await this.mailerService.sendMail({
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
