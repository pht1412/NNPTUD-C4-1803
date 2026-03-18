let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
const fs = require('fs')
const path = require('path')

const publicKey = fs.readFileSync(path.join(__dirname, '../public.pem'))

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token) {
                res.status(401).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            if (token.startsWith('Bearer ')) {
                token = token.slice(7, token.length);
            }
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
            if (result.exp * 1000 < Date.now()) {
                res.status(401).send({
                    message: "phien dang nhap het han"
                })
                return;
            }
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                res.status(401).send({
                    message: "khong tim thay nguoi dung"
                })
                return;
            }
            req.user = user;
            next()
        } catch (error) {
            res.status(401).send({
                message: "ban chua dang nhap"
            })
        }
    }
}