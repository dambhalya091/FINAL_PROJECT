require("dotenv").config();
const express = require("express");
const mongoose =require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("./models/User");
const auth = require("./middleware/auth");

const app = express();
app.use(express.json());


app.get("/",(req,res)=>{
res.status(200).json({
    message :" jwt login"
})


});


app.post("/api/auth/register", async (req,res)=>{

try{

const {name,email,password}=req.body;

if(!name || !email || !password){
return res.status(400).json({
   message : "password, name, email all required"
})


};

 if (typeof name !== "string" ||  typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({
        message: "Name, email and password all in strings"
      });
    }


if(!name.trim() || !email.trim()){

return res.status(400).json({

message : "email or name cant not empty"

});



};

if(password.length  < 6){

return res.status(400).json({
message : " password atleast 6 charachter"

});



};


const normalizedEmail = email.trim().toLowerCase();


const existingUser = await User.findOne({
      email: normalizedEmail
    });

 if (existingUser) {
      return res.status(409).json({
        message: "Email already registered"
      });
    }
    
 const hashedPassword = await bcrypt.hash(password, 10);

  const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword
    });
 return res.status(201).json({
      message: "User registered sucsessfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });

}catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "Email already registeed"
      });
    }

    console.error("Register error:", error.message);

    return res.status(500).json({
      message: "Internal server error"
    });
  }

});



app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Valid email and password are required"
      });
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase()
    }).select("+password");

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const isPasswordCorrect = await bcrypt.compare(
      password,
      user.password
    );

    if (!isPasswordCorrect) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      { id: user._id.toString() },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "1d" }
    );

    return res.status(200).json({
      message: "Login successful",
      token: token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      message: "Internal server error"
    });
  }
});


app.get("/api/auth/profile", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-password"
    );

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    return res.status(200).json({
      message: "Profile fetched successfully",
      user: user
    });
  } catch (error) {
    console.error("Profile error:", error.message);

    return res.status(500).json({
      message: "Internal server error"
    });
  }
});



const startServer = async () => {
  try {
    if (!process.env.MONGO_URI || !process.env.JWT_SECRET) {
      throw new Error("MONGO_URI and JWT_SECRET are required in .env");
    }

    await mongoose.connect(process.env.MONGO_URI);
    console.log("MongoDB connected successfully");

    const PORT = process.env.PORT || 5000;

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Startup error:", error.message);
    process.exit(1);
  }
};

startServer();