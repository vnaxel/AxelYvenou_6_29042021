const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cryptojs = require("crypto-js")
const User = require('../models/User')

require('dotenv').config()

exports.signup = (req, res, next) => {
    const emailCryptoJs = cryptojs.HmacSHA256(req.body.email, `${process.env.CRYPTOJS_EMAIL}`).toString()
    bcrypt.hash(req.body.password, 10)
    .then(hash => {
        const user = new User({
            email: emailCryptoJs,
            password: hash
        })
        user.save()
            .then(() => res.status(201).json({ message: 'Utilisateur créé !'}))
            .catch(error => res.status(400).json({ error }))
    })
    .catch(error => res.status(500).json({ error }))
}

exports.login = (req, res) => {
    const emailCryptoJs = cryptojs.HmacSHA256(req.body.email, `${process.env.CRYPTOJS_EMAIL}`).toString();
    User.findOne({ email: emailCryptoJs })
    .then((user) => {
        if (!user) {
            return res.status(401).json({ error: "Utilisateur inexistant" });
        }
        bcrypt.compare(req.body.password, user.password)
        .then(valid => {
            if (!valid) {
                return res.status(401).json({ error: 'Mot de passe incorrect'})
            }
            return res.status(200).json({
                userId: user._id,
                token: jwt.sign(
                    { userId: user._id},
                    process.env.TOKEN_SECRET,
                     { expiresIn: '24h'}                           
                )
            })
        })
        .catch(error => res.status(500).json({ error }))
    })
    .catch(error => res.status(500).json({ error }))
}