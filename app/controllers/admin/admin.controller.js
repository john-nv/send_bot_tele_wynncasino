const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
require('dotenv').config()

const { accountSchema, configSchema } = require('../../../schemas')
const { bcrypt, jsonWebToken } = require('../../util')
const secretKey = process.env.JWT_SECRET;

const ID_MONGO_DB = {
  ACCOUNT_ADMIN: '65f90f2f1de564708baf38ad',
  CONFIG: '65f914d32c133a628611081b'
}

class adminControllers {

  async login(req, res) {
    try {
      const { user, pass } = req.body
      const accountDb = await accountSchema.findOne({ user })
      if (!accountDb) return res.status(200).json({ code: 0, message: 'Tài khoản không tồn tại' })
      const isCheck = await bcrypt.bcryptCompare(accountDb.pass, pass)
      if (!isCheck) return res.status(200).json({ code: 0, message: 'Sai tài khoản hoặc mật khẩu' })
      const jwtCode = await jsonWebToken.generateJWT({ user })
      return res.status(201).json({ code: 1, jwt: jwtCode })
    } catch (error) {
      console.error(error)
      res.json({ message: error.message })
    }
  }

  async verifyJWT(req, res, next) {
    try {
      const { token } = req.body;
      const decodedPayload = await jwt.verify(token, secretKey);
      if (!decodedPayload) return res.status(200).json({ code: 0, message: 'Phiên đăng nhập hết hạn' });
      return res.status(200).json({ code: 1, message: 'Còn hạn sử dụng' });
    } catch (error) {
      console.error('JWT:', error.message);
      return res.status(200).json({ code: 0, message: 'Phiên đăng nhập hết hạn' });
    }
  }

  async mdwVerifyJWT(req, res, next) {
    try {
      const { token } = req.body;
      if (!token) return res.status(401).json({ code: 0, message: 'Token không tồn tại' });
      const decodedPayload = await jwt.verify(token, secretKey);
      if (!decodedPayload) return res.status(401).json({ code: 0, message: 'Phiên đăng nhập hết hạn' });
      req.user = decodedPayload;
      next();
    } catch (error) {
      console.error('Lỗi xác thực JWT:', error.message);
      return res.status(500).json({ code: 0, message: 'Lỗi xác thực JWT' });
    }
  }

  async editConfig(req, res) {
    try {
      let { btnStartDialog, msgUserSend, msgBotReply, msgBotWelcome, placeholderHome, placeholderUsername, titleHome, titleUsername } = req.body;

      const dataUpdate = {
        btnStartDialog,
        msgBotReply,
        msgBotWelcome,
        placeholderHome,
        placeholderUsername,
        titleHome,
        titleUsername,
        msgUserSend,
      };
      console.log(dataUpdate)
      const a = await configSchema.updateOne({ _id: ID_MONGO_DB.CONFIG }, dataUpdate);
      console.log(a)
      return res.status(201).json({ code: 1, message: 'Thay đổi thành công' });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ code: 0, message: 'Thay đổi thất bại' });
    }
  }

  async getConfig(req, res) {
    try {
      const data = await configSchema.findOne({ _id: ID_MONGO_DB.CONFIG });
      if (!data) return res.status(404).json({ code: 0, message: 'Không tìm thấy cấu hình' });

      return res.status(200).json({ code: 1, message: 'Thành công', data });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ code: 0, message: 'Thay đổi thất bại' });
    }
  }
}

module.exports = new adminControllers