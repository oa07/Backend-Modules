const Joi = require('@hapi/joi');
const dotenv = require('dotenv');

dotenv.config();

const envSchema = Joi.object({
  NODE_ENV: Joi.string()
    .allow(['development', 'production', 'test', 'provision'])
    .default('development'),
  PORT: Joi.number().default(3000),
  MONGODB_HOST: Joi.string().required(),
  JWT_ACCESS_KEY: Joi.string().required(),
  JWT_REFRESH_KEY: Joi.string().required(),
  EMAIL_ID: Joi.string().required(),
  EMAIL_PASSWORD: Joi.string().required(),
  JWT_ACCESS_KEY_EXPIRE_TIME: Joi.string().default('30m'),
  JWT_REFRESH_KEY_EXPIRE_TIME: Joi.string().default('24h')
})
  .unknown()
  .required();

const { error, value: validatedEnv } = Joi.validate(process.env, envSchema);
if (error) throw new Error(`Config validation error: ${error.message}`);

module.exports = {
  env: validatedEnv.NODE_ENV,
  port: validatedEnv.PORT,
  mongodbHost: validatedEnv.MONGODB_HOST,
  jwtAccessKey: validatedEnv.JWT_ACCESS_KEY,
  jwtRefreshKey: validatedEnv.JWT_REFRESH_KEY,
  emailID: validatedEnv.EMAIL_ID,
  emailPassword: validatedEnv.EMAIL_PASSWORD,
  jwtAccessKeyExpireTime: validatedEnv.JWT_ACCESS_KEY_EXPIRE_TIME,
  jwtRefreshKeyExpireTime: validatedEnv.JWT_REFRESH_KEY_EXPIRE_TIME
};
