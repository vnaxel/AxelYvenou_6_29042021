const express = require('express');
const mongoose = require('mongoose')
const path = require('path')

const sauceRoutes = require('./routes/sauce')
const userRoutes = require('./routes/user')

mongoose.connect('mongodb+srv://axel_admin:27372737@cluster0.bxs3f.mongodb.net/myFirstDatabase?retryWrites=true&w=majority',
  { useNewUrlParser: true,
    useUnifiedTopology: true })
  .then(() => console.log('Connexion à MongoDB réussie !'))
  .catch(() => console.log('Connexion à MongoDB échouée !'))

const app = express();

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content, Accept, Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
  next();
});

app.use(express.json())

app.use('/images', express.static(path.join(__dirname, 'images')))

app.use('/api/sauces', sauceRoutes)
app.use('/api/auth', userRoutes)

module.exports = app;