const { StatusCodes } = require("http-status-codes");
const jwt = require("jsonwebtoken");
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer")) {
    return res.status(StatusCodes.UNAUTHORIZED).json({ msg: " invalid" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const { username, userId } = jwt.verify(token, process.env.JWT_SECRET);
    req.user = {
      username,
      userId,
    };

    next();
  } catch (error) {
    return res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ msg: "Token is not valid" });
  }
}

module.exports = authMiddleware;
