import { sign } from 'jsonwebtoken';
import { randomBytes, createTransport } from 'crypto';
import { differenceInHours } from 'date-fns';
import { Manager } from '../../entities/managers';

export const generateAccessToken = (user: Manager): string => {
  const expiresIn = 24 * 60 * 60; // 24 hours in seconds
  return sign(
    {
      id: user.id,
      email: user.email,
      // Additional claims can be added here if necessary
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn }
  );
};

export const generateRefreshToken = (user: Manager, rememberInHours: number): string => {
  const expiresIn = rememberInHours * 60 * 60; // Convert hours to seconds
  return sign(
    {
      id: user.id,
      email: user.email,
      // Additional claims can be added here if necessary
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn }
  );
};

export const generateTokens = (managerId: string, accessExpiresIn: number, refreshExpiresIn: number) => {
  const manager = fetchManagerDetails(managerId);

  const accessTokenExpiresIn = accessExpiresIn * 60 * 60; // Convert hours to seconds
  const refreshTokenExpiresIn = refreshExpiresIn * 60 * 60; // Convert hours to seconds

  const access_token = sign(
    { 
      id: manager.id,
      email: manager.email,
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: accessTokenExpiresIn }
  );

  const refresh_token = sign(
    { 
      id: manager.id,
      email: manager.email,
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: refreshTokenExpiresIn }
  );

  return { // Return the tokens along with their expiration times
    access_token: access_token,
    refresh_token: refresh_token,
    expires_in: accessTokenExpiresIn, // already in seconds
    refresh_token_expires_in: refreshTokenExpiresIn, // already in seconds
  };
};

export const validateTokenExpiration = (sentAt: Date, expiresInHours: number): boolean => {
  const currentDateTime = new Date();
  const hoursDifference = differenceInHours(currentDateTime, sentAt);
  return hoursDifference < expiresInHours;
};

export const confirmManagerEmail = async (token: string): Promise<Manager> => {
  const manager = await fetchManagerByConfirmationToken(token);
  if (!manager) {
    throw new Error('Confirmation token is not valid');
  }

  if (!validateTokenExpiration(manager.confirmation_sent_at, email_expired_in)) {
    throw new Error('Confirmation token is expired');
  }

  manager.confirmed_at = new Date();
  return manager;
};

export const sendConfirmationEmail = async (email: string, token: string): Promise<void> => {
  const transporter = createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USERNAME,
    to: email,
    subject: 'Confirm your account',
    html: `<p>Welcome ${email}!</p>
<p>You can confirm your account email through the link below:</p>
<p><a href="${process.env.FRONTEND_URL}/confirm?confirmation_token=${token}">Confirm Email</a></p>`,
  };

  await transporter.sendMail(mailOptions);
};

export const generateConfirmationToken = async (): Promise<string> => {
  return new Promise((resolve, reject) => {
    randomBytes(32, (err, buffer) => {
      if (err) {
        reject(err);
      } else {
        resolve(buffer.toString('hex'));
        // The token is 32 bytes long and encoded in hexadecimal format
      }
    });
  });
};

export const resetPasswordRequest = async (email: string): Promise<void> => {
  const manager = await Manager.findOne({ where: { email: email } });
  if (!manager) {
    return; // If manager is not found, exit the function
  }

  const passwordResetToken = await generateConfirmationToken();
  manager.reset_password_token = passwordResetToken;
  manager.reset_password_sent_at = new Date();
  await manager.save();

  const transporter = createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USERNAME,
    to: email,
    subject: 'Reset your password',
    html: `<p>Hello ${manager.name}</p>
<p>Someone has requested a link to change your password. You can do this through the link below. </p>
<p><a href="${process.env.FRONTEND_URL}/reset-password?reset_token=${passwordResetToken}">Reset Password</a></p>
<p>If you didn't request this, please ignore this email. Your password won't change until you access the link above and create a new one.</p>`,
  };

  await transporter.sendMail(mailOptions);
};

function fetchManagerDetails(managerId: string): Manager {
  // This function should be implemented to fetch the manager details
  // For example, it could look up the manager in the database by the managerId
  // This is a placeholder function for the purpose of this example
  return {
    id: managerId,
    email: 'manager@example.com',
    // other manager properties
  } as Manager;
}

async function fetchManagerByConfirmationToken(token: string): Promise<Manager | null> {
  // This function should be implemented to fetch the manager by the confirmation token
  // For example, it could look up the manager in the database by the token
  // This is a placeholder function for the purpose of this example
  return null; // Replace with actual lookup logic
}

const email_expired_in = 24; // Assuming 24 hours for email confirmation expiration
