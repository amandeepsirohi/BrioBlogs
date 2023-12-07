import express from "express";
import mongoose from "mongoose";
import "dotenv/config";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";


// let path = "./"+ toString(process.env.PATH_JSON)+".json"
import serviceAccountKey from "./secret.json" assert { type: "json" };
import { getAuth } from "firebase-admin/auth";
//Schemas
import User from "./Schema/User.js";

const app = express();
const PORT = process.env.PORT;

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey)
});

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; 
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; 

app.use(express.json());
app.use(cors());

mongoose
  .connect(process.env.DB_LOCATION, { autoIndex: true })
  .then(console.log("Connected to DB successfully!"));

const formatDatatoSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};
     
const generateUsername = async (email) => {
  let username = email.split("@")[0];

  let usernameExists = await User.exists({
    "personal_info.username": username,
  }).then((result) => result);

  usernameExists ? (username += nanoid().substring(1, 4)) : "";
  return username;
};

app.post("/signup", (req, res) => {
  let { fullname, email = undefined, password } = req.body;

  //Validate data
  if (fullname.length < 3) {
    return res
      .status(403)
      .json({ error: "Full Name must be at least 3 letters" });
  }
  if (!email.length) {
    return res.status(403).json({ error: "Email can't be empty" });
  }
  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: "Invalid email" });
  }
  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      error:
        "Password should be at least 6 letters with 1 numeric , 1 lowercase and 1 uppercase letter ",
    });
  }

  bcrypt.hash(password, 10, async (err, hashed_password) => {
    let username = await generateUsername(email);
    let user = new User({
      personal_info: { fullname, email, password: hashed_password, username },
    });

    user
      .save()
      .then((u) => {
        return res.status(200).json(formatDatatoSend(u));
      })
      .catch((err) => {
        if (err.code == 11000) {
          res.status(500).json({ error: "Email already exists " });
        }
        return res.json(500).json({ error: err.message });
      });
  });

  //   return res.status(200).json({ status: "okay" });
});

app.post("/signin", (req, res) => {
  let { email, password } = req.body;
  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ error: "Email not found" });
      }

      if (!user.google_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res
              .status(403)
              .json({ error: "Error occurred while logging in ! try again" });
          }
          if (!result) {
            return res.status(403).json({ error: "Incorrect Password" });
          } else {
            return res.status(200).json(formatDatatoSend(user));
          }
        });
      }
      else{
        return res.status(403).json({"error" :"This mail used in google auth use another"});
      }
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

app.post("/google-auth", async (req, res) => {
  let { access_token } = req.body;

  getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
      let { email, name, picture } = decodedUser;

      picture = picture.replace("s96-c", "s384-c");

      let user = await User.findOne({ "personal_info.email": email })
        .select(
          "personal_info.fullname personal_info.username personal_info.profile_img personal_info.google_auth "
        )
        .then((u) => {
          return u || null;
        })
        .catch((err) => {
          return res.status(500).json({ error: err.message });
        });

      if (user) {
        if (user.google_auth) {
          return res.status(403).json({
            error:
              "This email is linked with google , login with password to access",
          });
        }
      } else {
        let username = await generateUsername(email);

        user = new User({
          personal_info: {
            fullname: name,
            email,
            username,
          },
          google_auth: true,
        });
        await user
          .save()
          .then((u) => {
            user = u;
          })
          .catch((err) => {
            return res.status(500).json({ error: err.message });
          });
      }
      return res.status(200).json(formatDatatoSend(user));
    })
    .catch((err) => {
      return res.status(500).json({ error: "Failed to authenticate with google" });
    });
});

app.listen(PORT, () => {
  console.log("listening on PORT => " + PORT);
});
