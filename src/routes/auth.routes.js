import { Router } from 'express';
import {
  login,
  register,
  logout,
  profile,
  verifyToken,
  forgetpassword,
  changepassword,
} from '../controllers/auth.controller.js';
import { authRequired } from '../middlewares/validateToken.js';
import { validateSchema } from '../middlewares/validator.middleware.js';
import { registerSchema, loginSchema, forgetPasswordSchema, changePasswordSchemma } from '../schemas/auth.schema.js';

const router = Router();
router.post('/login', validateSchema(loginSchema), login);
router.post('/register', validateSchema(registerSchema), register);
router.post('/forgetpassword', validateSchema(forgetPasswordSchema), forgetpassword)
router.post('/changepassword', validateSchema(changePasswordSchemma), changepassword)
router.post('/logout', logout);
router.get('/verify', verifyToken);
router.get('/profile', authRequired, profile);

export default router;
