const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const validateRegisterInput = require("../validation/registerValidation");
const jwt = require("jsonwebtoken");
const requiresAuth = require("../middleware/permissions");

// @route   GET /api/auth/test
// @desc Test the auth route
// @access Public
router.get("/test", (req, res) => {
  res.send("Auth route is working!");
});

// @route   GET /api/auth/register
// @desc Create a new user
// @access Public
router.post("/register", async (req, res) => {
  try {
    const { errors, isValid } = validateRegisterInput(req.body);

    if (!isValid) {
      return res.status(400).json(errors);
    }
    // check existing user
    const existingEmail = await User.findOne({
      email: new RegExp("^" + req.body.email + "$", "i"),
    });

    if (existingEmail) {
      return res.status(400).json({ error: "The email has been taken" });
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 12);
    // create a new user
    const newUser = new User({
      email: req.body.email,
      password: hashedPassword,
      name: req.body.name,
    });

    const savedUser = await newUser.save();

    const userToRetrun = { ...savedUser._doc };
    delete userToRetrun.password;

    return res.json(userToRetrun);
  } catch (error) {
    console.log(error);

    res.status(500).send(error.message);
  }
});

// @route   POST /api/auth/loggin
// @desc Login and return access token
// @access Public
router.post("/login", async (req, res) => {
  try {
    // check user
    const user = await User.findOne({
      email: new RegExp("^" + req.body.email + "$", "i"),
    });

    if (!user) {
      return res
        .status(400)
        .json({ error: "Problem found with your login credentials" });
    }

    const passwordMatch = await bcrypt.compare(
      req.body.password,
      user.password
    );

    if (!passwordMatch) {
      return res.status(400).json({ error: "Password not match" });
    }

    const payload = { userId: user._id };

    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("access-token", token, {
      expires: new Date(Date.now() + 7 * 60 * 60 * 1000),
      httpOnly: true, // cannot access by console or code
      secure: process.env.NODE_ENV === "production",
    });

    const userToRetrun = { ...user._doc };
    delete userToRetrun.password;

    return res.json({
      token: token,
      user: userToRetrun,
    });
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

// @route   GET /api/auth/current
// @desc Return current authed user
// @access Private
router.get("/current", requiresAuth, (req, res) => {
  if (!req.user) {
    return res.status(401).send("Unauthorized");
  }

  return res.json(req.user);
});

module.exports = router;
