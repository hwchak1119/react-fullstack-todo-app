const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");

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

    return res.json(savedUser);
  } catch (error) {
    console.log(error);

    res.status(500).send(error.message);
  }
});

module.exports = router;
