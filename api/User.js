const express = require("express");
const router = express.Router();

//password handler
const bcrypt = require("bcrypt");

//user model
const User = require("./../models/User.js");

//signup
router.post("/signup", (req, res) => {
  let { name, email, password, dateOfBirth } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();
  dateOfBirth = dateOfBirth.trim();

  if (name == "" || email == "" || password == "" || dateOfBirth == "") {
    res.json({
      status: "FAILED",
      message: "fill all fields",
    });
  } else if (!/^[a-zA-Z ]*$/.test(name)) {
    res.json({
      status: "FAILED",
      message: "Invalid Name",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    res.json({
      status: "FAILED",
      message: "Invalid Email",
    });
  } else if (!new Date(dateOfBirth).getTime()) {
    res.json({
      status: "FAILED",
      message: "Invalid DOB",
    });
  } else if (password.length < 8) {
    res.json({
      status: "FAILED",
      message: "password should have 8 or more characters",
    });
  } else {
    //check if user already exists
    User.find({ email })
        .then((result) => {
          if (result.length) {
            //user already exists
            res.json({
              status: "FAILED",
              message: "User with this email already exists",
            });
          } else {
            //create new user

            //encrypt password
            const saltRounds = 10;
            bcrypt
              .hash(password, saltRounds)
              .then((hashedPassword) => {
                const newUser = new User({
                  name,
                  email,
                  password: hashedPassword,
                  dateOfBirth,
                });

                newUser
                  .save()
                  .then((result) => {
                    res.json({
                      status: "SUCCESS",
                      message: "signup successful",
                      data: result,
                    });
                  })
                  .catch((err) => {
                    res.json({
                      status: "FAILED",
                      message: "An error occurred while saving user account!",
                    });
                  });
              })
              .catch((err) => {
                res.json({
                  status: "FAILED",
                  message: "An error occured while hashing password!",
                });
              });
          }
        })
        .catch((err) => {
          console.error(err);
          res.json({
            status: "FAILED",
            message: "Error occured while checking for existing user!",
          });
        })
    ;
  }
});

//signin

router.post("/signin", (req, res) => {});

module.exports = router;
