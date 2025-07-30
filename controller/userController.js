const { use } = require("bcrypt/promises");
const db = require("../db/dbConfig");
const bcrypt = require("bcrypt");
const { StatusCodes } = require("http-status-codes");
const { json } = require("express");
const jwt = require("jsonwebtoken");
require("dotenv").config();

async function register(req, res) {
  const saltRounds = await bcrypt.genSalt(10);
  const { username, firstname, lastname, email, password } = req.body;

  if (!username || !firstname || !lastname || !email || !password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Please provide all information" });
  }

  try {
    // Connect to the database (reused connection)
    db.connectToDb();

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const existingUser = await db.client.query(
      "SELECT username, userid FROM users WHERE username = $1 OR email = $2",
      [username, email]
    );
    if (existingUser.rows.length > 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "user already exist" });
    }
    // Insert the user data into the database
    await db.client.query(
      "INSERT INTO users (username, firstname, lastname, email, password) VALUES ($1, $2, $3, $4, $5)",
      [username, firstname, lastname, email, hashedPassword]
    );

    return res
      .status(StatusCodes.CREATED)
      .json({ msg: "User created successfully" });
  } catch (error) {
    console.error(error.message);
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Something went wrong, try later" });
  }
}

async function login(req, res) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Please provide all information" });
  }
  try {
    const user = await db.client.query(
      "SELECT username, email, userid, password FROM users WHERE email = $1",
      [email]
    );
    const token = jwt.sign(
      { userId: user.rows[0].userid, username: user.rows[0].username },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d", // Token will expire in 1 day
      }
    );
    const isMatch = await bcrypt.compare(password, user.rows[0].password);

    if (user.rows.length === 0 || !isMatch) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "Invalid credentials" });
    } else {
      // res.json({ user: user.rows });
      res.status(200).json({
        msg: "Login successful",
        token,
        username: user.rows[0].username,
        email: user.rows[0].email,
        userId: user.rows[0].userid,
      });
    }
  } catch (error) {
    console.error(error.message);
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Something went wrong, try later" });
  }
}
async function checkUser(req, res) {
  const username = req.user.username;
  const userid = req.user.userId;
  return res
    .status(StatusCodes.OK)
    .json({ msg: "Valid user", username, userid });
}

const resetPassword = async (req, res) => {
  const { email, otp, password } = req.body;

  // Validate OTP format: Ensure it's a 6-digit number
  const otpRegex = /^\d{6}$/;
  if (!otpRegex.test(otp)) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "OTP must be a 6-digit number" });
  }
  try {
    const [user] = await dbConnection.query(
      "SELECT * from users WHERE email=? AND otp=? AND otp_expires > ?",
      [email, otp, new Date()]
    );

    if (user.length == 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "Invalid or Expired OTP" });
    }
    // hash the new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    //  update the user's password and clear the OTP and it's expiration
    await dbConnection.query(
      "UPDATE users SET password=?, otp= NULL, otp_expires=NULL WHERE email=?",
      [hashedPassword, email]
    );

    return res.status(StatusCodes.OK).json({
      msg: "Password reset successfully. You can now log in with your new password",
    });
  } catch (error) {
    console.error(error);
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Server error. Please try again later." });
  }
};

const requestOTP = async (req, res) => {
  const { email } = req.body;

  try {
    const [user] = await dbConnection.query(
      "SELECT * from users WHERE email=?",
      [email]
    );

    if (!user) {
      return res.status(StatusCodes.NOT_FOUND).json({ msg: "user not found" });
    }

    // generate OTP using userUtility
    const otp = userUtility.generateDigitOTP();

    // for 10 min
    const expireAt = new Date(Date.now() + 10 * 60 * 1000);

    // store the otp and expiration on database
    await dbConnection.query(
      "UPDATE users SET otp =?, otp_expires=? WHERE email=?",
      [otp, expireAt, email]
    );

    // send the otp using via email using userUtility
    await userUtility.sendEmail(email, otp);
    res.status(StatusCodes.OK).json({ msg: "OTP sent to your email address" });
  } catch (error) {
    console.error(error);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      msg: "Server error, Please try again later.",
    });
  }
};

module.exports = { register, login, checkUser, resetPassword, requestOTP };
const { Pool } = require("pg");
require("dotenv").config();

const client = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: process.env.SSL_REJECT_UNAUTHORIZED === "true",
  },
});

async function connectToDb() {
  try {
    await client.connect();
    console.log("Database connected successfully");
  } catch (err) {
    console.error("Connection error", err.stack);
  }
}

module.exports = {
  client,
  connectToDb,
};
