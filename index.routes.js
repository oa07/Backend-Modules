const express = require('express');
const router = express.Router();
const authentication = require('./server/auth/auth.route');

router.use('/auth', authentication);

module.exports = router;
