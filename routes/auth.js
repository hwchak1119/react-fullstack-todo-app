const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const validateRegisterInput = require("../validation/registerValidation");

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

    return res.json({ passwordMatch: passwordMatch });
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

module.exports = router;
