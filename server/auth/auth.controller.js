const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { AuthModel } = require('./auth.model');
const config = require('../../config/config');
const logger = require('../../config/logger');

const {
  sendMailForgetPasswordToken,
  sendMailVerifyAccount
} = require('../hepler/mail');

const {
  registerVal,
  loginVal,
  forgetPasswordVal,
  resetPasswordVal,
  createNewPasswordVal
} = require('./auth.validation');

const asyncHandler = require('../middleware/async');
const ErrorResponse = require('../utils/errorResponse');
const redis = require('../../index.redis');

exports.register = asyncHandler(async (req, res, next) => {
  const { error } = registerVal(req.body);
  if (error) return next(new ErrorResponse(error.details[0].message, 400));
  const { username, email, password, phoneNumber, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new AuthModel({
    username,
    email,
    phoneNumber,
    role,
    password: hashedPassword
  });

  const token = crypto.randomBytes(20).toString('hex');
  const verifyToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
  user.verifyAccountToken = verifyToken;
  await sendMailVerifyAccount(user.username, user.email, verifyToken);

  await user.save();
  return res.status(201).json({ success: true });
});

exports.login = asyncHandler(async (req, res, next) => {
  const { error } = loginVal(req.body);
  if (error) return next(new ErrorResponse(error.details[0].message, 400));

  const { email, password } = req.body;
  let user = await AuthModel.findOne({ email }).select('+password');
  if (!user) return next(new ErrorResponse('User not found', 404));

  const isMatched = await bcrypt.compare(password, user.password);
  if (isMatched) {
    if (!user.isAccountActive) {
      user.isAccountActive = true;
      await user.save();
    }

    const accessToken = await jwt.sign(
      { id: user._id, username: user.username },
      config.jwtAccessKey,
      { expiresIn: config.jwtAccessKeyExpireTime }
    );
    const refreshToken = await jwt.sign(
      { id: user._id, username: user.username },
      config.jwtRefreshKey,
      { expiresIn: config.jwtRefreshKeyExpireTime }
    );

    return res.status(200).json({
      success: true,
      accessToken,
      refreshToken
    });
  }

  return next(new ErrorResponse('Password not matching', 401));
});

exports.currentUser = asyncHandler(async (req, res, next) => {
  return res.status(200).json({ success: true, user: req.user });
});

// exports.verifyAccountSendToken = asyncHandler(async (req, res, next) => {
//   const user = await AuthModel.findById(req.body.userID);

//   if (user.isAccountVerified)
//     return next(new ErrorResponse('Account is already verified', 400));

//   const token = crypto.randomBytes(20).toString('hex');
//   const verifyToken = crypto
//     .createHash('sha256')
//     .update(token)
//     .digest('hex');
//   user.verifyAccountToken = verifyToken;
//   await user.save();
//   await sendMailVerifyAccount(user.username, user.email, verifyToken);
//   return res.status(200).json({ success: true, verifyToken });
// });

exports.verifyAccountReceiveToken = asyncHandler(async (req, res, next) => {
  const { token } = req.params;
  const user = await AuthModel.findOne({
    verifyAccountToken: token
  });
  if (!user) return next(new ErrorResponse('User not found', 404));
  user.verifyAccountToken = undefined;
  user.isAccountVerified = true;
  await user.save();
  return res.status(200).json({ success: true });
});

exports.forgetPasswordSendToken = asyncHandler(async (req, res, next) => {
  const { error } = forgetPasswordVal(req.body);
  if (error) return next(new ErrorResponse(error.details[0].message, 400));
  const resetToken = crypto.randomBytes(20).toString('hex');

  const { email } = req.body;
  const user = await AuthModel.findOne({ email });
  if (!user) return next(new ErrorResponse('User not found', 404));

  const token = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  user.resetPasswordToken = token;
  user.resetPasswordExpire = Date.now() + 10 * 60 * 1000;

  await user.save();
  await sendMailForgetPasswordToken(user.username, user.email, token);
  return res.status(200).json({ success: true, token });
});

exports.forgetPasswordRecieveToken = asyncHandler(async (req, res, next) => {
  const { token } = req.params;
  const user = await AuthModel.findOne({
    resetPasswordToken: token,
    resetPasswordExpire: { $gt: Date.now() }
  });
  if (!user) return next(new ErrorResponse('Token Expired !!', 401));
  await user.save();
  return res.status(200).json({ success: true, token });
});

exports.resetPassword = asyncHandler(async (req, res, next) => {
  const { error } = resetPasswordVal(req.body);
  if (error) return next(new ErrorResponse(error.details[0].message, 400));

  const user = await AuthModel.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpire: { $gt: Date.now() }
  });
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  user.isAccountVerified = true;

  user.password = await bcrypt.hash(req.body.password, 10);
  await user.save();
  return res.status(200).json({ success: true });
});

exports.createNewPassword = asyncHandler(async (req, res, next) => {
  const { oldPassword, newPassword } = req.body;
  const { error } = createNewPasswordVal(req.body);
  if (error) return next(new ErrorResponse(error.details[0].message, 400));

  const user = await AuthModel.findById(req.user._id).select('+password');

  const isMatched = await bcrypt.compare(oldPassword, user.password);
  if (isMatched) {
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    return res.status(200).json({ success: true });
  }
  return next(new ErrorResponse('Old password is not matching', 401));
});

exports.updateDetails = asyncHandler(async (req, res, next) => {
  let { username, email, phoneNumber } = req.body;
  if (!username) username = req.user.username;
  if (!email) email = req.user.email;
  if (!phoneNumber) phoneNumber = req.user.phoneNumber;

  const fieldsToUpdate = { username, email, phoneNumber };

  const user = await AuthModel.findByIdAndUpdate(req.user._id, fieldsToUpdate, {
    new: true
  });

  res.status(200).json({ success: true, user });
});

exports.deactivateAccount = asyncHandler(async (req, res, next) => {
  const { user } = req;
  user.isAccountActive = false;
  await user.save();
  return res.status(200).json({ success: true, user });
});

exports.deleteAccount = asyncHandler(async (req, res, next) => {
  await AuthModel.findByIdAndDelete({ _id: req.user._id });
  req.user = undefined;
  return res.status(200).json({ success: true });
});

exports.tokenRefresher = asyncHandler(async (req, res, next) => {
  const refreshToken = req.body.refreshToken;

  try {
    const isBlackListed = await redis.get(`BlackListed${refreshToken}`);
    if (isBlackListed) {
      return next(new ErrorResponse('This Token is already used', 403));
    }
    const decoded = await jwt.verify(refreshToken, config.jwtRefreshKey);
    const user = await AuthModel.findById(decoded.id);
    if (!user) return next(new ErrorResponse('User not found', 404));

    const accessToken = await jwt.sign(
      { id: user._id, username: user.username },
      config.jwtAccessKey,
      { expiresIn: config.jwtAccessKeyExpireTime }
    );

    return res.status(201).json({ success: true, accessToken });
  } catch (err) {
    return next(
      new ErrorResponse('Refresh Token is Expired !! Login again', 401)
    );
  }
});

exports.logout = asyncHandler(async (req, res, next) => {
  const { refreshToken } = req.body;
  const { accessToken } = req;
  if (!refreshToken)
    return next(new ErrorResponse('Refresh Token not found!! ', 404));

  await redis.set(`BlackListed${refreshToken}`, accessToken, 'EX', 30 * 60);
  await redis.set(`BlackListed${accessToken}`, refreshToken, 'EX', 24 * 3600);
  return res.status(200).json({ success: true });
});
