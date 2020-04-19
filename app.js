require('dotenv').config();
require('./mongod');
const express = require('express');
const bodyParser = require('body-parser');
const { errors } = require('celebrate');
const helmet = require('helmet');
const cors = require('cors');
const { requestLogger, errorLogger } = require('./middlewares/logger');
const rootRouter = require('./routes/index');
const { limiter } = require('./rate limiter/rate-limiter');
const errorsCentr = require('./middlewares/errors');

const { PORT = 3000 } = process.env;

const app = express();
app.use(cors());
app.use(limiter);
app.use(helmet());
app.use(helmet.noCache());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(requestLogger);

app.use(rootRouter);

app.use(errorLogger);

app.use(errors());

app.use(errorsCentr);

app.listen(PORT, () => {
});
