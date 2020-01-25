const { createLogger, format, transports } = require('winston');
const winston = require('winston');

const getLabel = callingModule => {
  const parts = callingModule.filename.split('/');
  return parts[parts.length - 2] + '/' + parts.pop();
};

const getLine = info => {
  if (info instanceof Error) {
    const stacklist = info.stack
      .split('\n')
      .slice()[1]
      .split(':');
    return `::${stacklist[stacklist.length - 2]}`;
  }
  return '';
};

module.exports = callingModule =>
  createLogger({
    level: 'info',
    format: format.combine(
      format.simple(),
      format.timestamp(),
      format.printf(
        info =>
          `[${info.timestamp}] - ${info.level}: [${getLabel(
            callingModule
          )}${getLine(info)}] ${info.message}`
      )
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
