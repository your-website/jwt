const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const { ERROR_EMAIL_NAME, NOT_VALID_URL } = require('../CONST/MESSAGE');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    minlength: 2,
    maxlength: 30,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator(validate) {
        return validator.isEmail(validate);
      },
      message: (props) => `${props.value} ${NOT_VALID_URL}`,
    },
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false,
  },
  prevPassword: {
    type: Array,
  },
  newpassword: {
    type: String,
    minlength: 8,
    select: false,
  },
});

userSchema.statics.findUserByCredentials = function check(name, password) {
  return this.findOne({ name }).select('+password')
    .then((user) => {
      if (!user) {
        return Promise.reject(new Error(ERROR_EMAIL_NAME));
      }

      return bcrypt.compare(password, user.password)
        .then((matched) => {
          if (!matched) {
            return Promise.reject(new Error(ERROR_EMAIL_NAME));
          }
          return user;
        });
    });
};

module.exports = mongoose.model('user', userSchema);
