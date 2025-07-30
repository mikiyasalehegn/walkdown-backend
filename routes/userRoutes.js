const express = require("express");
const router = express.Router();
const {
  register,
  login,
  checkUser,
  requestOTP,
  resetPassword,
} = require("../controller/userController");

// Authentication miidle ware

const authMiddleware = require("../middleware/authMiddlware");

// register route
router.post("/register", register);

// login user
router.post("/login", login);

// login user
router.get("/check", authMiddleware, checkUser);

// route to request an otp for password reset
router.post("/forgot-password", requestOTP);
// route to reset password using otp
router.post("/reset-password", resetPassword);

module.exports = router;
