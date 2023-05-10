require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const { errors } = require('celebrate');
const bodyParser = require('body-parser');
const helmet = require('helmet');

const cors = require('./middlewares/cors');
const { requestLogger, errorLogger } = require('./middlewares/logger');

const { PORT = 3001 } = process.env;
const app = express();
mongoose.connect('mongodb://127.0.0.1:27017/mestodb');

app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors);

const NotFoundError = require('./errors/NotFoundError');
const userRouter = require('./routes/users');
const cardRouter = require('./routes/cards');
const { loginUser, createUser } = require('./controllers/users');
const { messageErr } = require('./constants/constants');
const handleErrors = require('./middlewares/handleErrors');
const auth = require('./middlewares/auth');
const { createUserValidation, loginValidation } = require('./middlewares/validation');

app.use(requestLogger); // подключаем логгер запросов за ним идут все обработчики роутов

app.get('/crash-test', () => {
  setTimeout(() => {
    throw new Error('Сервер сейчас упадёт');
  }, 0);
});

app.post('/signin', loginValidation, loginUser);
app.post('/signup', createUserValidation, createUser);
app.use(auth);
app.use('/cards', cardRouter);
app.use('/users', userRouter);

app.use('*', () => {
  throw new NotFoundError(messageErr.notFound.page);
});

app.use(errorLogger); // нужно подключить после обработчиков роутов и до обработчиков ошибок
app.use(errors());
app.use(handleErrors);

app.listen(PORT);

// ssh aleks123@158.160.36.89
// https://mesto-avtor-HohlovAleks.nomoredomains.club
// api.mesto-avtor-hohlov-al.nomoredomains.club
// 69c9b2e92a586e3c693fee194130235a111e68941c5896d14c3f93cea01fbb37

// chmod +x /home/aleks123/react-mesto-api-full/frontend/build
// root /home/aleks123/react-mesto-api-full/frontend/build
// sudo chown -R $USER:www-data /home/aleks123/react-mesto-api-full/frontend/build
// scp -r ./build/* aleks123@158.160.36.89:/home/aleks123/react-mesto-api-full/frontend/build
// scp ./.env aleks123@158.160.36.89:/home/aleks123/react-mesto-api-full/backend

// sudo nano /etc/nginx/sites-available/default
// sudo nano /etc/nginx/nginx.conf
// sudo nano ./.env
// sudo nano ./app.js
// sudo nano ./middlewares/cors.js

// scp -r ./* aleks123@158.160.36.89:/home/aleks123/react-mesto-api-full/backend
// scp -r ./build/* aleks123@158.160.36.89:/home/aleks123/react-mesto-api-full/backend
// sudo ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/enabled
// sudo certbot install --cert-name mesto-avtor-HohlovAleks.nomoredomains.club --nginx
