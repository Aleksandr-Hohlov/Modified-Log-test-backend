const Card = require('../models/card');
// const User = require('../models/user');
const {
  messageErr,
  ValidationError,
  CastError,
  messageErrDefault,
  messageSuccessDel,
} = require('../constants/constants');

const BadRequestError = require('../errors/BadRequestError');
const ForbiddenError = require('../errors/ForbiddenError');
const NotFoundError = require('../errors/NotFoundError');

const getAllCards = (req, res, next) => {
  Card.find({})
    .then((card) => res.send(card))
    .catch((err) => next(err));
};

const createCard = (req, res, next) => {
  const { name, link } = req.body;
  const owner = req.user._id;
  console.log(req.user);
  Card.create({ name, link, owner })
    .then((card) => res.send(card))
    .catch((err) => {
      if (err.name === ValidationError) {
        next(new BadRequestError(messageErr.badRequest.card));
      } else {
        next(err);
      }
    });
};

const deleteCard = (req, res, next) => {
  Card.findById(req.params.cardId)
    .orFail(() => new NotFoundError(messageErr.notFound.card))
    .then((card) => {
      if (!card.owner.equals(req.user._id)) {
        return next(new ForbiddenError(messageErr.badRequest.forbiddenDel));
      }
      return card.remove().then(() => res.send({ message: messageSuccessDel }));
    })
    .catch(next);
};

// prettier-ignore
const likeCard = (req, res, next) => Card.findByIdAndUpdate(
  req.params.cardId,
  { $addToSet: { likes: req.user._id } },
  {
    new: true,
    runValidators: true,
  },
)
  .then((card) => {
    if (!card) {
      throw new NotFoundError(messageErr.notFound.card);
    }
    return res.send(card);
  })
  .catch((err) => {
    if (err.name === CastError) {
      next(new BadRequestError(messageErr.badRequest.cardLike));
    } else {
      next(err);
    }
  });

// prettier-ignore
const dislikeCard = (req, res, next) => Card.findByIdAndUpdate(
  req.params.cardId,
  { $pull: { likes: req.user._id } },
  {
    new: true,
    runValidators: true,
  },
)
  .then((card) => {
    if (!card) {
      throw new NotFoundError(messageErr.notFound.cardLike);
    }
    return res.send(card);
  })
  .catch((err) => {
    if (err.name === CastError) {
      next(new BadRequestError(messageErrDefault));
    } else {
      next(err);
    }
  });

module.exports = {
  getAllCards,
  createCard,
  deleteCard,
  likeCard,
  dislikeCard,
};
