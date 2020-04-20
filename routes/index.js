const router = require('express').Router();
const middlewaresauth = require('../middlewares/auth');
const NotFoundError = require('../errors/NotFoundError');
const auth = require('./auth');
const { NOT_FOUND_ERROR } = require('../CONST/MESSAGE');

router.use(auth);
router.use(middlewaresauth);
router.use('/', require('./users'));

router.use(() => {
  throw new NotFoundError(NOT_FOUND_ERROR);
});

module.exports = router;
