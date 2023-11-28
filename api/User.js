const nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");
const express = require("express");
const router = express.Router();
require("dotenv").config();

//path for static pages
const path = require("path");

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

  // hash unique string
  const saltRounds = 10;
  bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
      // set values in userVerification collection
      const newVerification = new UserVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 21600000,
      });

      newVerification
        .save()
        .then(() => {
          transporter
            .sendMail(mailOption)
            .then(() => {
              // Email sent successfully
              console.log("Verification email sent!");
              // Do not send a response here, as it's already being handled by the calling function
            })
            .catch((err) => {
              // Handle email sending failure
              console.error(err);
              // Send a response indicating email failure
              res.json({
                status: "FAILED",
                message: "Verification email failed!",
              });
            });
        })
        .catch((err) => {
          // Handle database saving failure
          console.error(err);
          // Send a response indicating database failure
          res.json({
            status: "FAILED",
            message: "Couldn't save verification email data!",
          });
        });
    })
    .catch(() => {
      // Handle hashing failure
      console.error("An error occurred while hashing email data!");
      // Send a response indicating hashing failure
      res.json({
        status: "FAILED",
        message: "An error occurred while hashing email data!",
      });
    });
};


//verify email
router.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;

  UserVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        //if verification data exists

        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;

        if (expiresAt < Date.now()) {
          //record expired to we delete it
          UserVerification.deleteOne({ userId })
            .then((result) => {
              User.deleteOne({ _id: userId })
                .then(() => {
                  let message = "Link has expires. Please sign up again";
                  return res.redirect(`/user/verified/error=true&message=${message}`);
                })
                .catch((error) => {
                  console.log(error);
                  let message = "Cleaning user with expired string failed";
                  return res.redirect(`/user/verified/error=true&message=${message}`);
                });
            })
            .catch((err) => {
              console.error(err);
              let message =
                "An error occurred while clearing expired user verification email";
              return res.redirect(`/user/verified/error=true&message=${message}`);
            });
        } else {
          //valid record exists so we validate the user string

          //compare hashed uniqus string

          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then((result) => {
              if (result) {
                //string match

                User.updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    UserVerification.deleteOne({ userId })
                      .then(() => {
                        res.sendFile(
                          path.join(__dirname, "../views/verified.html")
                        );
                      })
                      .catch((err) => {
                        console.error(err);
                        let message =
                          "An error occurred while finalizing successful validation";
                        return res.redirect(
                          `/user/verified/error=true&message=${message}`
                        );
                      });
                  })
                  .catch((error) => {
                    let message =
                      "An error occurred while updating user verification";
                    return res.redirect(
                      `/user/verified/error=true&message=${message}`
                    );
                  });
              } else {
                //record is incorrect
                let message = "Invalid details passed. Check your inbox";
                return res.redirect(`/user/verified/error=true&message=${message}`);
              }
            })
            .catch((err) => {
              let message = "An error occurred while comparing unique string";
              return res.redirect(`/user/verified/error=true&message=${message}`);
            });
        }
      } else {
        let message =
          "Account record doesnt exist or has been verified already. Please sign up or login";
        return res.redirect(`/user/verified/error=true&message=${message}`);
      }
    })
    .catch((err) => {
      console.error(err);
      let message =
        "An error occurred while checking existing user verification email";
      return res.redirect(`/user/verified/error=true&message=${message}`);
    });
});

//verified page route
router.get("/verified", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/verified.html"));
});

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
          //check if user is verified
          if (!data[0].verified) {
            res.json({
              status: "FAILED",
              message: "Email is not verified yet. Check your inbox",
            });
          } else {
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
          }
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
