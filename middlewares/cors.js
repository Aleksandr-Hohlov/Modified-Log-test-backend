const allowedCors = [
  'https://praktikum.tk',
  'http://praktikum.tk',
  'localhost:3000',
  'localhost:3001',
  'http://mesto-avtor-hohlovaleks.nomoredomains.club',
  'http://mesto-avtor-hohlovaleks.nomoredomains.club/cards',
  'http://mesto-avtor-hohlovaleks.nomoredomains.club/',
  'http://mesto-avtor-hohlovaleks.nomoredomains.club/users/me',
  'https://mesto-avtor-hohlovaleks.nomoredomains.club',
  'mesto-avtor-hohlovaleks.nomoredomains.club',
  'http://localhost:3000',
  'http://localhost:3001',
  'http://api.mesto-avtor-Hohlov-Al.nomoredomains.club',
  'https://api.mesto-avtor-Hohlov-Al.nomoredomains.club',
  'api.mesto-avtor-Hohlov-Al.nomoredomains.club',
  'https://mesto-avtor-hohlovaleks.nomoredomains.club/cards',
  'https://mesto-avtor-hohlovaleks.nomoredomains.club/',
  'https://mesto-avtor-hohlovaleks.nomoredomains.club/users/me',
  'https://localhost:3000',
  'http://api.mesto-avtor-Hohlov-Al.nomoredomains.club/users/me',
  'https://api.mesto-avtor-Hohlov-Al.nomoredomains.club/users/me',
  'http://api.mesto-avtor-Hohlov-Al.nomoredomains.club/users',
  'https://api.mesto-avtor-Hohlov-Al.nomoredomains.club/users',
];

const cors = (req, res, next) => {
  const { origin } = req.headers;
  const DEFAULT_ALLOWED_METHODS = 'GET,HEAD,PUT,PATCH,POST,DELETE';
  const requestHeaders = req.headers['access-control-request-headers'];

  if (allowedCors.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', true);
  }

  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Methods', DEFAULT_ALLOWED_METHODS);
    res.header('Access-Control-Allow-Headers', requestHeaders);
    return res.end();
  }
  return next();
};

module.exports = cors;
