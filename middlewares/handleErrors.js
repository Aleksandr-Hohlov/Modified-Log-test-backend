const { err500, messageErrServer } = require('../constants/constants');

module.exports = (err, req, res, next) => {
  const { statusCode = err500, message } = err;
  res.status(statusCode).send({
    message: statusCode === err500 ? messageErrServer : message,
  });
  next();
};
