const mongoose = require('mongoose');
const validator = require('validator');
// const User = require('./user');

const cardSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    minlength: 2,
  },
  link: {
    type: String,
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'user',
    required: true,
  },

  likes: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'user',
      default: [],
    },
  ],
  createdAt: {
    type: Date,
    default: Date.now(),
  },
});

module.exports = mongoose.model('card', cardSchema);
