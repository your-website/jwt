const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const Unauthorized = require('../errors/Unauthorized');
const NotFoundError = require('../errors/NotFoundError');
const {
  NO_FOUND_USER, ERROR_EMAIL_NAME, NO_USER_ID, YES_USER, YES_EMAIL, ERROR_PASSWORD,
} = require('../CONST/MESSAGE');

const { DEV_SECRET } = require('../CONST/DEV_SECRET');

const { NODE_ENV, JWT_SECRET } = process.env;

function getUser(req, res, next) {
  User.findById(req.user._id)
    .then((user) => {
      if (!user) {
        throw new NotFoundError(NO_FOUND_USER);
      } else {
        res.send({ data: user });
      }
    })
    .catch(next);
}

function login(req, res, next) {
  const { name, password } = req.body;
  return User.findUserByCredentials(name, password)
    .then((user) => {
      if (!user) {
        throw new Unauthorized(ERROR_EMAIL_NAME);
      }
      const token = jwt.sign(
        { _id: user._id },
        NODE_ENV === 'production' ? JWT_SECRET : DEV_SECRET,
        { expiresIn: '7d' },
      );
      res.send({ token });
    })
    .catch(() => {
      next(new Unauthorized(ERROR_EMAIL_NAME));
    });
}

function createUser(req, res, next) {
  const { name, email, password } = req.body;
  User.findOne({ email })
    .then((hasEmail) => {
      if (hasEmail) {
        throw new NotFoundError(YES_EMAIL);
      }
    })
    .catch(next);
  User.findOne({ name })
    .then((user) => {
      if (user) {
        throw new NotFoundError(YES_USER);
      } else {
        bcrypt.hash(password, 10)
          .then((hash) => User.create({
            name,
            email,
            password: hash,
            prevPassword: hash,
          }))
          .then((data) => {
            res.status(201).send({
              _id: data._id,
              email: data.email,
            });
          })
          .catch(next);
      }
    })
    .catch(next);
}

function changePassword(req, res, next) {
  const { name, password } = req.body;
  const hasPasswordElements = [];
  User.findOne({ name })
    .then((data) => {
      const { prevPassword } = data;
      prevPassword.forEach(async (element) => {
        const matched = await bcrypt.compare(password, element);
        hasPasswordElements.push(matched);
      });
      return prevPassword;
    })
    .then((prevPassword) => {
      bcrypt.hash(password, 10)
        .then((hash) => {
          const hasPassword = hasPasswordElements.some((hasFalse) => hasFalse === true);
          if (hasPassword) {
            throw new NotFoundError(ERROR_PASSWORD);
          }
          if (prevPassword.length >= 5) {
            User.findOneAndUpdate({ name }, {
              $pop: { prevPassword: -1 },
            })
              .catch((err) => res.status(500).send({ message: `Произошла ошибка + ${err}` }));
          }
          User.findOneAndUpdate({ name }, {
            password: hash,
            $push: { prevPassword: { $each: [hash], $slice: 5 } },
          })
            .then((user) => {
              if (!user) {
                throw new NotFoundError(NO_USER_ID);
              }
              res.status(201).send({
                _id: user._id,
                email: user.email,
              });
            });
        })
        .catch(next);
    })
    .catch((err) => res.status(500).send({ message: `Произошла ошибка + ${err}` }));
}

module.exports = {
  getUser, login, createUser, changePassword,
};
