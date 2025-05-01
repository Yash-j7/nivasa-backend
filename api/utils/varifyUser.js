import jwt from "jsonwebtoken";
import { throwError } from "./error.js";

// export const verifyToken = (req, res, next) => {
//   const tooken = req.cookies.access_token;
//   if (!tooken) return next(throwError(401, "Session End. Login Again! "));
//   jwt.verify(tooken, process.env.JWT_SECRET, (err, user) => {
//     if (err) return next(throwError(403, "Frbidden"));
//     req.user = user;
//     next();
//   });
// };
// First, let's modify your verifyToken middleware to be more robust:

export const verifyToken = (req, res, next) => {
  console.log("Headers:", req.headers);
  console.log("Cookies:", req.cookies);

  const token =
    req.cookies.access_token ||
    (req.headers.authorization && req.headers.authorization.split(" ")[1]) ||
    req.query.token;

  console.log("Token found:", !!token);

  if (!token) return next(throwError(401, "Session End. Login Again!"));

  try {
    console.log("JWT_SECRET exists:", !!process.env.JWT_SECRET);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error("Token verification error:", err.message, err.name);
    return next(throwError(403, "Forbidden: Invalid token"));
  }
};
