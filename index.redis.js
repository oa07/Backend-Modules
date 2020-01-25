const Redis = require('ioredis');
Redis.Promise = require('bluebird');
const redis = new Redis();
module.exports = redis;
