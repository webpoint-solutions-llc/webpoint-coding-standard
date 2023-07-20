import ms from 'ms';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import httpStatus from 'http-status';
import { User } from '@prisma/client';
import createError from 'http-errors';
import { JwtPayload } from 'jsonwebtoken';

import token from '../../../lib/token';
import { config } from '../../../config';
import { redisClient } from '../../../lib/redis';
import { sendMail } from '../email/email.service';
import { userService } from '../user/user.service';
import { tokenService } from '../token/token.service';

const register = async (registrationToken: string, user: User) => {
  const decoded = token.verify({ token: registrationToken, audience: 'registration' }) as JwtPayload;
  const userId = decoded.sub as string;

  const existingUser = await userService.getUserById(userId);

  if (existingUser?.password) throw createError(httpStatus.CONFLICT, 'User already registered');

  const hashedPassword = await bcrypt.hash(user.password as string, Number(config.bcrypt.saltRounds));

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { password, ...createdUserWithoutPassword } = await userService.updateUserById(userId, {
    ...user,
    isEmailVerified: true,
    password: hashedPassword,
  });

  return createdUserWithoutPassword;
};

const login = async (email: string, password: string) => {
  const user = await userService.getUserByEmail(email);

  if (!user) {
    throw createError(httpStatus.BAD_REQUEST, 'Invalid email or password');
  }

  // if login attempts exceeded 5 times, throw error
  const failedLoginAttempts = await redisClient.get(`failedLoginAttempts:${user.id}`);

  if (Number(failedLoginAttempts) >= 5) {
    throw createError(httpStatus.TOO_MANY_REQUESTS, 'Too many failed login attempts');
  }

  if (!user.isActive || !user.password) {
    throw createError(httpStatus.FORBIDDEN, 'User is deactivated');
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    // deactivating user if failed login attempts exceeded 5 times
    const failedLoginAttempts = await redisClient.incr(`failedLoginAttempts:${user.id}`);
    if (failedLoginAttempts >= 5) {
      userService.updateUserById(user.id, { isActive: false });
    }

    throw createError(httpStatus.BAD_REQUEST, 'Invalid email or password');
  }

  // reset failed login attempts
  await redisClient.del(`failedLoginAttempts:${user.id}`);

  return sendMFACode(user.id);
};

const verifyEmail = async (emailVerificationToken: string) => {
  const decoded = token.verify({ token: emailVerificationToken, audience: 'emailVerification' }) as JwtPayload;

  const user = await userService.getUserById(decoded.sub as string);

  if (!user) throw createError(httpStatus.UNAUTHORIZED, 'Invalid or expired token');
  if (user.isEmailVerified) throw createError(httpStatus.BAD_REQUEST, 'Email already verified');

  return userService.updateUserById(user.id, { isEmailVerified: true });
};

const resetPassword = async (resetPasswordToken: string, newPassword: string) => {
  const decoded = token.verify({ token: resetPasswordToken, audience: 'passwordReset' }) as JwtPayload;

  const user = await userService.getUserById(decoded.sub as string);

  if (!user) throw createError(httpStatus.UNAUTHORIZED, 'Invalid or expired token');

  const hashedPassword = await bcrypt.hash(newPassword, Number(config.bcrypt.saltRounds));
  return userService.updateUserById(user.id, { password: hashedPassword });
};

const sendMFACode = async (userId: string) => {
  const user = await userService.getUserById(userId);
  const MFACodeExpiration = ms(config.mfaToken.expiresIn) / 1000;

  if (!user) throw createError(httpStatus.UNAUTHORIZED, 'Invalid or expired token');

  // Generate a 4-digit random number
  const code = crypto.randomInt(1000, 9999);

  // Save the code to the redis store
  redisClient.setex(userId, MFACodeExpiration, code.toString());

  // Send the code to the user's email address
  await sendMail({
    to: user.email,
    subject: 'MFA Code',
    template: 'mfa',
    context: {
      mfaCode: code,
      firstName: user.fullName?.split(' ')[0],
      loginUrl: config.clientUrl.login,
    },
  });

  return tokenService.generateMFAToken(user);
};

const resendMFACode = async (mfaToken: string) => {
  const decoded = token.verify({ token: mfaToken, audience: 'mfa' }) as JwtPayload;

  if (!decoded.sub) throw createError(httpStatus.UNAUTHORIZED, 'Invalid or expired token');

  const user = await userService.getUserById(decoded.sub);

  if (!user) throw createError(httpStatus.UNAUTHORIZED, 'Invalid or expired token');

  return sendMFACode(user.id);
};

const verifyMFACode = async (mfaToken: string, mfaCode: string) => {
  const decoded = token.verify({ token: mfaToken, audience: 'mfa' }) as JwtPayload;

  if (!decoded.sub) throw createError(httpStatus.UNAUTHORIZED, 'Invalid or expired token');

  const user = await userService.getUserById(decoded.sub);

  if (!user) throw createError(httpStatus.UNAUTHORIZED, 'Invalid or expired MFA session');

  // Get the code from the redis store
  const redisCode = await redisClient.get(user.id);

  if (redisCode !== mfaCode) throw createError(httpStatus.UNAUTHORIZED, 'Invalid or expired MFA Code');

  // Delete the code from the redis store
  await redisClient.del(user.id);

  const accessToken = await tokenService.generateAccessToken(user);
  const refreshToken = await tokenService.generateRefreshToken(user);

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { password, ...userWithoutPassword } = user;

  return { user: userWithoutPassword, accessToken, refreshToken };
};

const getRegistrationDetailsFromToken = async (registrationToken: string) => {
  const decoded = token.verify({ token: registrationToken, audience: 'registration' }) as JwtPayload;

  if (!decoded.sub) throw createError(httpStatus.UNAUTHORIZED, 'Invalid or expired token');

  const user = await userService.getUserById(decoded.sub, { populateFields: ['business'] });

  if (user?.password) throw createError(httpStatus.CONFLICT, 'User already registered');
  return user;
};

export const getUserDetailsByMFAToken = async (mfaToken: string) => {
  const decoded = token.verify({ token: mfaToken, audience: 'mfa' }) as JwtPayload;

  if (!decoded.sub) throw createError(httpStatus.UNAUTHORIZED, 'Invalid or expired token');

  const user = await userService.getUserById(decoded.sub);

  return {
    email: user?.email,
    fullName: user?.fullName,
    isActive: user?.isActive,
    isEmailVerified: user?.isEmailVerified,
  };
};

export const sendPasswordResetLink = async (email: string) => {
  const user = await userService.getUserByEmail(email);

  // As a user may be invited but not registered yet, we need to ensure that they have followed the onboarding process
  if (!user?.isEmailVerified) throw createError(httpStatus.BAD_REQUEST, 'User not found');

  const passwordResetToken = await tokenService.generatePasswordResetToken(user.id);

  return sendMail({
    to: user.email,
    subject: 'Reset Password',
    template: 'forgot-password',
    context: {
      passwordResetUrl: `${config.clientUrl.forgotPassword}/${passwordResetToken}`,
      firstName: user.fullName?.split(' ')[0],
    },
  });
};

export const authService = {
  verifyEmail,
  register,
  login,
  resetPassword,
  sendMFACode,
  resendMFACode,
  verifyMFACode,
  sendPasswordResetLink,
  getUserDetailsByMFAToken,
  getRegistrationDetailsFromToken,
};
