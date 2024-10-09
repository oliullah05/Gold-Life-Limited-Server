import express from 'express'
import auth from '../../middlewares/auth'
import validateRequest from '../../middlewares/validateRequest'
import { AuthControllers } from './auth.controller'
import { AuthValidations } from './auth.validation'
import { USER_ROLE } from '../user/user.constant'


const router = express.Router()

router.post('/login', validateRequest(AuthValidations.loginValidationSchema), AuthControllers.loginUser)

router.post(
  '/change-password',
  auth(USER_ROLE.admin, USER_ROLE.user),
  validateRequest(AuthValidations.changePasswordValidationSchema),
  AuthControllers.changePassword
)

router.post(
  '/refresh-token',
  validateRequest(AuthValidations.refreshTokenValidationSchema),
  AuthControllers.refreshToken
)

router.post(
  '/forget-password',
  validateRequest(AuthValidations.forgetPasswordValidationSchema),
  AuthControllers.forgetPassword
)

router.post(
  '/reset-password',
  validateRequest(AuthValidations.resetPasswordValidationSchema),
  AuthControllers.resetPassword
)

export const AuthRoutes = router
