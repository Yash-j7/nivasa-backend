import bcrypt from "bcrypt";
import User from "../models/user.models.js";
import { throwError } from "../utils/error.js";
import jwt from "jsonwebtoken";
import { passwordGenarator, usernameGenarator } from "../utils/helper.js";

//======handle singup route ===========//
export const singup = async (req, res, next) => {
  const { username, email, password } = req.body;

  if (!password || password.trim() === "") {
    return next(throwError(400, "Password is required"));
  }

  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({
      success: true,
      message: "User created successfully",
    });
  } catch (error) {
    next(error);
  }
};

// ========sing in route handling here =====//
// ======== Sign-in Route Handling ===== //
export const signin = async (req, res, next) => {
  const { email, userPassword } = req.body;

  try {
    // Find user by email
    const validUser = await User.findOne({ email });
    if (!validUser) {
      return next(throwError(404, "Wrong Credentials!"));
    }

    // Verify password
    const isValidPassword = bcrypt.compareSync(
      userPassword,
      validUser.password
    );
    if (!isValidPassword) {
      return next(throwError(401, "Wrong Credentials!"));
    }

    // Destructure and exclude password
    const { password, ...rest } = validUser._doc;

    // Generate JWT
    const token = jwt.sign(
      { id: validUser._id },
      process.env.JWT_SECRET,
      { expiresIn: "30d" } // Matches the cookie's maxAge
    );

    // Set secure cookie with token
    res
      .cookie("access_token", token, {
        httpOnly: true,
        secure: false, // Keep false for HTTP
        sameSite: "lax", // Change from "strict"
        maxAge: 30 * 24 * 60 * 60 * 1000,
      })
      .status(200)
      .json({ token, rest });
  } catch (error) {
    console.error("Error during sign-in:", error);
    next(error); // Pass the error to your error handler middleware
  }
};

//=====Handle Google Singin Here ======//
export const googleSignIn = async (req, res, next) => {
  const { email, name, photo } = req.body;
  try {
    const user = await User.findOne({ email });

    //====IF user exist in DB====//
    if (user) {
      const tooken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "720h",
      });

      const { password, ...rest } = user._doc;
      res
        .cookie("access_token", tooken, { httpOnly: true, secure: true })
        .status(200)
        .json(rest);
    }
    //====IF user not exist in DB====//
    else {
      const hashedPassword = bcrypt.hashSync(passwordGenarator(), 10);
      const newUser = new User({
        name,
        username: usernameGenarator(name),
        email,
        password: hashedPassword,
        avatar: photo,
      });
      const user = await newUser.save();
      const tooken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "720h",
      });
      const { pass: password, ...rest } = user._doc;
      res
        .cookie("access_token", tooken, { httpOnly: true, secure: true })
        .status(200)
        .json(rest);
    }
  } catch (error) {
    //======Handling Error Here =====//
    next(throwError(error));
  }
};

//=====handle signout=====//
export const signOut = async (req, res, next) => {
  try {
    res.clearCookie("access_token");
    res.status(200).json("User Deleted Successfully!");
  } catch (error) {
    next(error);
  }
};
