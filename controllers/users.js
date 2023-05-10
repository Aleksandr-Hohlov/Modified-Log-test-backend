const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const {
  messageErr,
  ValidationError,
  CastError,
  messageErrDefault,
} = require('../constants/constants');

const { NODE_ENV, JWT_SECRET } = process.env;

const BadRequestError = require('../errors/BadRequestError');
const UnauthorizedError = require('../errors/UnauthorizedError');
const ConflictError = require('../errors/ConflictError');
const NotFoundError = require('../errors/NotFoundError');

const getAllUsers = (req, res, next) => {
  User.find({})
    .then((users) => res.send(users))
    .catch(next);
};

const getUserById = (req, res, next) => {
  User.findById(req.params.userId)
    .then((user) => {
      if (!user) {
        throw new NotFoundError(messageErr.notFound.user);
      } else {
        res.status(200).send({ data: user });
      }
    })
    .catch((err) => {
      if (err.name === CastError) {
        next(new BadRequestError(messageErr.badRequest.getUserById));
      } else {
        next(err);
      }
    });
};

const getUser = (req, res, next) => {
  User.findById(req.user._id)
    .then((user) => {
      if (!user) {
        throw new NotFoundError(messageErr.notFound.user);
      } else {
        res.status(200).send({ data: user });
      }
    })
    .catch((err) => {
      if (err.name === CastError) {
        next(new BadRequestError(messageErrDefault));
      } else {
        next(err);
      }
    });
};

// prettier-ignore
const createUser = (req, res, next) => {
  const {
    name, avatar, email, password, age, city, education,
  } = req.body;
  bcrypt
    .hash(password, 10)
    .then((hash) => User.create({
      name,
      age,
      city,
      education,
      avatar,
      email,
      password: hash,
    }))
    .then(() => res.send({
      data: {
        name,
        age,
        city,
        education,
        avatar,
        email,
      },
    }))
    .catch((err) => {
      if (err.name === ValidationError) {
        return next(new BadRequestError(messageErr.badRequest.createUser));
      }
      if (err.code === 11000) {
        return next(new ConflictError(messageErr.badRequest.conflictEmail));
      }
      return next(err);
    });
};

const loginUser = (req, res, next) => {
  const { email, password } = req.body;
  User.findUserByCredentials(email, password)
    .then((user) => {
      const token = jwt.sign(
        { _id: user._id },
        NODE_ENV === 'production' ? JWT_SECRET : 'salt-salt-salt',
        { expiresIn: '1d' },
      );
      res.send({ token });
    })
    .catch(() => {
      next(new UnauthorizedError(messageErr.badRequest.unauthorized));
    });
};

const updateUserInfo = (req, res, next) => {
  const { name, age, city, education } = req.body;
  User.findByIdAndUpdate(
    req.user._id,
    { name, age, city, education },
    {
      new: true,
      runValidators: true,
    },
  )
    .then((user) => {
      if (user) {
        res.send(user);
      }
    })
    .catch((err) => {
      if (err.name === ValidationError || err.name === CastError) {
        next(new BadRequestError(messageErr.badRequest.updateUserInfo));
      } else {
        next(err);
      }
    });
};

const updateAvatar = (req, res, next) => {
  const { avatar } = req.body;
  User.findByIdAndUpdate(req.user._id, { avatar }, { new: true, runValidators: true })
    .then((user) => {
      if (!user) {
        throw new NotFoundError(messageErr.notFound.user);
      } else {
        res.status(200).send({ data: user });
      }
    })
    .catch((err) => {
      if (err.name === ValidationError || err.name === CastError) {
        next(new BadRequestError(messageErr.badRequest.updateAvatar));
      } else {
        next(err);
      }
    });
};

module.exports = {
  getUserById,
  getAllUsers,
  createUser,
  updateUserInfo,
  updateAvatar,
  loginUser,
  getUser,
};
