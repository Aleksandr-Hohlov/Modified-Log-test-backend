const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    minLength: 3,
    maxLength: 30,
    required: true,
  },
  age: {
    type: Number,
    min: 10,
    max: 99,
    default: '18',
    required: true,
  },
  city: {
    type: String,
    minLength: 3,
    maxLength: 30,
    default: 'Город',
    required: true,
  },
  education: {
    type: String,
    minLength: 3,
    maxLength: 30,
    default: 'ВУЗ',
    required: true,
  },

  avatar: {
    type: String,
    required: true,
    validate: {
      validator: (v) => validator.isURL(v),
      message: 'Неправильный формат ссылки',
    },
    default: 'https://i.postimg.cc/KcKLDp2t/images123.png',
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: (v) => validator.isEmail(v),
      message: 'Неправильный формат email',
    },
  },
  password: {
    type: String,
    required: true,
    select: false,
  },
});

// eslint-disable-next-line func-names
userSchema.statics.findUserByCredentials = function (email, password) {
  return this.findOne({ email })
    .select('+password')
    .then((user) => {
      if (!user) {
        return Promise.reject(new Error('Неправильные почта или пароль'));
      }
      return bcrypt.compare(password, user.password).then((res) => {
        if (!res) {
          return Promise.reject(new Error('Неправильные почта или пароль'));
        }
        return user;
      });
    });
};

module.exports = mongoose.model('user', userSchema);
