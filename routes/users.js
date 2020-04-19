const router = require('express').Router();
const { celebrate, Joi } = require('celebrate');

const {
  getUser,
} = require('../controllers/users');

router.get('/users/me', celebrate({
  body: Joi.object().keys({
    _id: Joi.string().required().length(24),
    name: Joi.string().required().min(2).max(30),
    email: Joi.string().required().email(),
    prevPassword: Joi.array().items(),
  }),
}), getUser);

module.exports = router;
