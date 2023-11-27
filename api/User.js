const nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");
const express = require("express");
const router = express.Router();
require("dotenv").config();

//password handler
const bcrypt = require("bcrypt");

//user model
const User = require("./../models/User.js");

//user model
const UserVerification = require("./../models/UserVerification.js");

//setup nodemailer
let transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_APP_PASS,
  },
});

//testing mailer
transporter.verify((error, success) => {
  if (error) {
    console.log("error");
    console.log(error);
  } else {
    console.log("success");
    console.log(success);
  }
});

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
                verified: false,
              });

              newUser
                .save()
                .then((result) => {
                  //handle email verification
                  sendVerificationEmail(result, res);
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
      });
  }
});

//send verification email function
const sendVerificationEmail = ({ _id, email, name }, res) => {
  const currentUrl = "http://localhost:3000/";

  const uniqueString = uuidv4() + _id;

  const mailOption = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify Your Email",
    html: `<h2>Email Verification</h2>

    <p>Hello ${name},</p>

    <p>Thank you for signing up! To complete your registration, please click the link below to verify your email:</p>

    <p><a href=${
      currentUrl + "user/verify/" + _id + "/" + uniqueString
    } style="text-decoration: none; background-color: #4CAF50; color: white; padding: 10px 15px; border-radius: 5px; display: inline-block;">Verify Email</a></p>

    <p>If you did not sign up for this account, you can ignore this email.</p>
    <p><b>Link expires in 6 hours</b></p>

    <p>Thank you,<br> [Your Company Name]</p>`,
  };

  //hash unique string
  const saltRounds = 10;
  bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
      //set values in userVerification collection
      const newVerification = new UserVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 21600000,
      });

      newVerification
        .save()
        .then(() => {
          transporter.sendMail(mailOption)
          .then(()=>{
            //email sent
            res.json({
              status: "PENDING",
              message: "Verification email sent!",
            });
          })
          .catch((err) => {
            console.log(err);
            res.json({
              status: "FAILED",
              message: "Verification email failed!",
            });
          });
        })
        .catch((err) => {
          console.log(err);
          res.json({
            status: "FAILED",
            message: "Couldn't send verification email data!",
          });
        });
    })
    .catch(() => {
      res.json({
        status: "FAILED",
        message: "An error occured while hashing email data!",
      });
    });
};

//signin

router.post("/signin", (req, res) => {
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email == "" || password == "") {
    res.json({
      status: "FAILED",
      message: "fill all fields",
    });
  } else {
    User.find({ email })
      .then((data) => {
        if (data.length) {
          const hashedPassword = data[0].password;
          bcrypt
            .compare(password, hashedPassword)
            .then((result) => {
              if (result) {
                res.json({
                  status: "SUCCESSFUL",
                  message: "Signin Successful",
                  data: data,
                });
              } else {
                res.json({
                  status: "FAILED",
                  message: "Invalid Password",
                });
              }
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "Error occured while comparing passwords",
              });
            });
        } else {
          res.json({
            status: "FAILED",
            message: "Invalid Credentials",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "FAILED",
          message: "An error occurred while checking for existing user!",
        });
      });
  }
});

module.exports = router;
