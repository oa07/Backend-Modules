const jwt = require('jsonwebtoken');
const config = require('../../config/config');
const { AuthModel } = require('../../server/auth/auth.model');
const redis = require('../../index.redis');
const asyncHandler = require('./async');
const ErrorResponse = require('../utils/errorResponse');

exports.verifyToken = asyncHandler(async (req, res, next) => {
  const bearerHeader = req.headers.authorization;
  if (bearerHeader && bearerHeader.startsWith('Bearer')) {
    const accessToken = bearerHeader.split(' ')[1];

    if (!accessToken) return next(new ErrorResponse('Not authorized !!', 401));

    try {
      const isBlackListed = await redis.get(`BlackListed${accessToken}`);
      if (isBlackListed) {
        return next(new ErrorResponse('This Token is already used', 403));
      }
      const decoded = await jwt.verify(accessToken, config.jwtAccessKey);
      const user = await AuthModel.findById(decoded.id);
      if (!user) return next(new ErrorResponse('User not found', 404));

      req.accessToken = accessToken;
      req.user = user;
      next();
    } catch (err) {
      return next(new ErrorResponse('Refersh this token !!', 401));
    }
  } else {
    return next(new ErrorResponse('Enter a valid token !!', 401));
  }
});
