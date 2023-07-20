import { Request, Response, NextFunction } from 'express';

import { config } from '../../../config';
import { authService } from './auth.service';
import { tokenService } from '../token/token.service';

export const register = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token: registrationToken } = req.params;
    const user = req.body;

    const registeredUser = await authService.register(registrationToken, user);

    return res.json({
      status: 'success',
      payload: registeredUser,
    });
  } catch (error) {
    return next(error);
  }
};

export const login = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body;

    const mfaToken = await authService.login(email, password);

    return res.json({
      status: 'success',
      mfaToken: mfaToken,
      payload: {},
    });
  } catch (error) {
    return next(error);
  }
};

export const verifyMFACode = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { mfaCode, mfaToken } = req.body;

    const { accessToken, refreshToken, user } = await authService.verifyMFACode(mfaToken, mfaCode);

    return res.cookie('refresh_token', refreshToken, config.cookie.refreshToken).json({
      status: 'success',
      payload: user,
      accessToken,
    });
  } catch (error) {
    return next(error);
  }
};

export const rotateToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const refreshToken = req.cookies.refresh_token;

    const { accessToken: newAccessToken, refreshToken: newRefreshToken } = await tokenService.rotateToken(refreshToken);

    return res.cookie('refresh_token', newRefreshToken, config.cookie.refreshToken).json({
      status: 'success',
      accessToken: newAccessToken,
      payload: {},
    });
  } catch (error) {
    return next(error);
  }
};

export const verifyEmail = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token: emailVerificationToken } = req.params;

    await authService.verifyEmail(emailVerificationToken);

    return res.json({
      status: 'success',
      payload: {},
    });
  } catch (error) {
    return next(error);
  }
};

export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token: resetPasswordToken } = req.params;
    const { password } = req.body;

    await authService.resetPassword(resetPasswordToken, password);

    return res.json({
      status: 'success',
      payload: {},
    });
  } catch (error) {
    return next(error);
  }
};

export const sendPasswordResetLink = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email } = req.body;

    await authService.sendPasswordResetLink(email);

    return res.json({
      status: 'success',
      payload: {},
    });
  } catch (error) {
    return next(error);
  }
};

export const getRegistrationDetails = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token: registrationToken } = req.params;

    const registrationDetails = await authService.getRegistrationDetailsFromToken(registrationToken);

    return res.json({
      status: 'success',
      payload: registrationDetails,
    });
  } catch (error) {
    return next(error);
  }
};

export const getUserDetailsByMFAToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token: mfaToken } = req.params;

    const userDetails = await authService.getUserDetailsByMFAToken(mfaToken);

    return res.json({
      status: 'success',
      payload: userDetails,
    });
  } catch (error) {
    return next(error);
  }
};

export const resendMFACode = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token: mfaToken } = req.params;

    const newMfaToken = await authService.resendMFACode(mfaToken);

    return res.json({
      status: 'success',
      payload: {
        mfaToken: newMfaToken,
      },
    });
  } catch (error) {
    return next(error);
  }
};
