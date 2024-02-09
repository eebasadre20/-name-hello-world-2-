import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class EmailUtil {
  constructor(private readonly mailerService: MailerService) {}

  async sendVerificationEmail(email: string, verificationToken: string): Promise<void> {
    const sanitizedEmail = this.sanitizeEmail(email);
    const verificationUrl = `https://yourdomain.com/verify?token=${verificationToken}`; // Replace with your frontend URL

    try {
      await this.mailerService.sendMail({
        to: sanitizedEmail,
        subject: 'Verify Your Email',
        template: './verification', // e.g., path to your email templates
        context: {
          // Data to be sent to template engine
          email: sanitizedEmail,
          verificationUrl,
          token: verificationToken,
        },
      });
    } catch (error) {
      // Log the error or handle it as per your application's error handling policies
      console.error('Failed to send verification email:', error);
      // Depending on your application's requirements, you might want to throw the error to be handled by the caller
      throw error;
    }
  }

  async sendVerificationConfirmationEmail(userEmail: string): Promise<void> {
    // ... existing code for sendVerificationConfirmationEmail
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const sanitizedEmail = this.sanitizeEmail(email);
    const passwordResetUrl = `https://yourdomain.com/reset-password?token=${token}`; // Replace with your frontend URL for password reset

    try {
      await this.mailerService.sendMail({
        to: sanitizedEmail,
        subject: 'Password Reset Instructions',
        template: './password-reset', // e.g., path to your email templates for password reset
        context: {
          // Data to be sent to template engine
          email: sanitizedEmail,
          passwordResetUrl,
          token,
        },
      });
    } catch (error) {
      // Log the error or handle it as per your application's error handling policies
      console.error('Failed to send password reset email:', error);
      // Depending on your application's requirements, you might want to throw the error to be handled by the caller
      throw error;
    }
  }

  async sendPasswordResetConfirmationEmail(userEmail: string): Promise<void> {
    // ... existing code for sendPasswordResetConfirmationEmail
  }

  sanitizeEmail(email: string): string {
    // Remove or encode potentially dangerous characters
    const sanitizedEmail = email.replace(/[\s;()<>\\\/'"]/g, '');
    return sanitizedEmail;
  }

  // ... other methods ...
}
