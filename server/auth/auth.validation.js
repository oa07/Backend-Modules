const joi = require('@hapi/joi');

exports.registerVal = data => {
  const compareWith = {
    username: joi
      .string()
      .min(4)
      .alphanum()
      .required(),
    email: joi
      .string()
      .email({ minDomainSegments: 2 })
      .min(6)
      .required(),
    password: joi
      .string()
      .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/)
      .min(6)
      .required(),
    phoneNumber: joi
      .string()
      .regex(/^[0-9]+$/)
      .length(11)
      .required(),
    role: joi
      .string()
      .allow(['admin', 'customer', 'worker']) // it is not giving error...
      .required()
  };
  return joi.validate(data, compareWith);
};

exports.loginVal = data => {
  const compareWith = {
    email: joi
      .string()
      .email({ minDomainSegments: 2 })
      .required(),
    password: joi.string().required()
  };
  return joi.validate(data, compareWith);
};

exports.forgetPasswordVal = data => {
  const compareWith = {
    email: joi
      .string()
      .email({ minDomainSegments: 2 })
      .required()
  };
  return joi.validate(data, compareWith);
};

exports.resetPasswordVal = data => {
  const compareWith = {
    password: joi
      .string()
      .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/)
      .min(6)
      .required()
  };
  return joi.validate(data, compareWith);
};

exports.createNewPasswordVal = data => {
  const compareWith = {
    oldPassword: joi.string().required(),
    newPassword: joi
      .string()
      .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/)
      .min(6)
      .required()
  };
  return joi.validate(data, compareWith);
};
