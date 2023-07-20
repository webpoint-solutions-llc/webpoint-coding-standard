import express from 'express';

import { validate } from '../../../middlewares/validateApiSchema';
import { registerSchema, loginSchema, resetPasswordSchema, verifyMfaCodeSchema } from './auth.api.schema';
import {
  register,
  login,
  rotateToken,
  verifyEmail,
  resetPassword,
  verifyMFACode,
  resendMFACode,
  sendPasswordResetLink,
  getRegistrationDetails,
  getUserDetailsByMFAToken,
} from './auth.controller';

const router = express.Router();

router.post('/login', validate(loginSchema), login);
router.post('/register/:token', validate(registerSchema), register);
router.get('/register/:token', getRegistrationDetails);
router.post('/rotate-token', rotateToken);
router.post('/verify-email/:token', verifyEmail);

// MFA routes
router.get('/mfa/:token', getUserDetailsByMFAToken);
router.post('/mfa/:token/resend', resendMFACode);
router.post('/mfa/verify', validate(verifyMfaCodeSchema), verifyMFACode);

router.post('/reset-password', sendPasswordResetLink);
router.post('/reset-password/:token', validate(resetPasswordSchema), resetPassword);

export default router;
