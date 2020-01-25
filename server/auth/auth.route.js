const express = require('express');
const router = express.Router();
const {
  register,
  login,
  currentUser,
  forgetPasswordSendToken,
  forgetPasswordRecieveToken,
  resetPassword,
  verifyAccountSendToken,
  verifyAccountReceiveToken,
  createNewPassword,
  updateDetails,
  deleteAccount,
  deactivateAccount,
  tokenRefresher,
  logout
} = require('./auth.controller');
const { verifyToken } = require('../middleware/authorization');

router.post('/register', register);
router.post('/login', login);
router.get('/currentUser', verifyToken, currentUser);

// router.post('/verifyAccount', verifyAccountSendToken);
router.get('/verifyAccount/:token', verifyAccountReceiveToken);

router.post('/forgetPassword', forgetPasswordSendToken);
router.get('/forgetPassword/:token', forgetPasswordRecieveToken);
router.post('/resetPassword/:token', resetPassword);

router.post('/createNewPassowrd', verifyToken, createNewPassword);
router.post('/updateDetails', verifyToken, updateDetails);

router.get('/deactivateAccount', verifyToken, deactivateAccount);
router.get('/deleteAccount', verifyToken, deleteAccount);

router.get('/token-refresher', tokenRefresher);
router.get('/logout', verifyToken, logout);
module.exports = router;
