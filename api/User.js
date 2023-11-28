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

//user verification model
const UserVerification = require("./../models/UserVerification.js");

//user otp verification model
const UserOtpVerification = require("./../models/UserOtpVerification.js");

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
                  sendOtpVerificationEmail(result, res);
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

//sendOtpVerificationEmail
const sendOtpVerificationEmail = async ({_id, email}, res)=>{
  try{
    const otp = `${Math.floor(1000 + Math.random() * 9000)}`

    const mailOptions ={
      from: process.env.AUTH_EMAIL,
      to: email,
      subject: "Verify Your Email",
      html: `<p>Hello,</p>

      <p>Thank you for signing up! To complete your registration, please use the following OTP (One-Time Password) to verify your email:</p>
      
      <h3 style="background-color: #4CAF50; color: white; padding: 10px; border-radius: 5px; display: inline-block;">${otp}</h3>
      
      <p>The OTP is only valid for 1 hour. If you did not sign up for this account, you can ignore this email.</p>
      
      <p>Thank you</p>
      `
    }

    const saltRounds =10

    const hashedOTP = await bcrypt.hash(otp, saltRounds)
    const newOTPVerification = await new UserOtpVerification({
      userId:_id,
      otp: hashedOTP,
      createdAt:Date.now(),
      expiresAt:Date.now() + 3600000,
    })

    await newOTPVerification.save();

    await transporter.sendMail(mailOptions);
    console.log("Verification email sent!");

  }catch(error){
    console.error(error);
  }
}

//verify otp 
router.post("/verify-otp", async (req, res)=>{
  try{
    let {userId, otp}= req.body;
    if(!userId||!otp){
      throw Error("Empty otp details are not allowed")
    }else{
      const UserOtpVerificationRecords = await UserOtpVerification.find({
        userId,
      })
      if(UserOtpVerificationRecords.length<=0){
        throw new Error("Account record doesnt exist or has already been verifies. Please signin or login")
      }else{
        const {expiresAt} = UserOtpVerificationRecords[0];
        const hashedOtp = UserOtpVerificationRecords[0].otp

        if(expiresAt<Date.now()){
          await UserOtpVerification.deleteMany({userId})
          throw new Error("code has expired. please request again")
        }else{
          const validOtp = await bcrypt.compare(otp, hashedOtp)

          if(!validOtp){
            throw new Error("invalid code passe. chec your inbox")
          }else{
            await User.updateOne({_id:userId}, {verified:true})
            await UserOtpVerification.deleteMany({userId})
            res.json({
              status:'VERIFIED',
              message:`user email verified successfully`
            })
          }
        }
      }
    }
  }catch(error){
    res.json({
      status:'FAILED',
      message:error.message
    })
  }
})

//resend
router.post('/resend-otp', async(req, res) => {
  try{
    let{userId, email} = req.body

    if(!userId || !email){
      throw new Error('Empty user details not allowed')
    }else{
      await UserOtpVerification.deleteMany({userId})
      sendOtpVerificationEmail({_id: userId, email}, res)
    }
  }catch(error){
    res.json({
      status:'FAILED',
      message:error.message
    })
  }
})

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
