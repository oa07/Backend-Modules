const { createLogger, format, transports } = require('winston');
const winston = require('winston');

module.exports = createLogger({
  level: 'info',
  format: format.combine(
    format.simple(),
    format.timestamp(),
    format.printf(info => `[${info.timestamp}] ${info.level}: ${info.message}`)
  ),
  defaultMeta: { service: 'user-service' },
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({
      filename: `${__dirname}/../logs/error.log`,
      level: 'error'
    }),
    new winston.transports.File({
      filename: `${__dirname}/../logs/info.log`,
      level: 'info'
    })
  ]
});
