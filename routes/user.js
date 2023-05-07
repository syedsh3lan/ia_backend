const express = require('express')
const router = express.Router()
const conn = require("../db/dbConnection");
const { body, validationResult } = require("express-validator");
const util = require("util");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
//Login
router.post (
    "/login",
    body("Email").isEmail().withMessage("please enter a valid email "),
    body("Password").isLength({ min :8, max:20}).withMessage("password should be (8-20) character"),
    async (req , res) => {
        try {
           const errors = validationResult(req) ;
           if(!errors.isEmpty()){
              return res.status(400).json({errors:errors.array()});
           }

           const query = util.promisify(conn.query).bind(conn);
           const user = await query(
            "select * from user where Email=?",
            [req.body.Email]
           );
           if (user.length == 0){
            return res.status(404).json({
                errors: [
                    {
                        msgs : "email or password not found"
                    } 
                ] 
            });
           } 


           const checkPassword = await bcrypt.compare(req.body.Password,
             user[0].Password);
           if (checkPassword){
            res.status(200).json(user); 
           }
           else{
            return res.status(404).json({ 
                errors: [
                    {
                        msgs : "email or password not found"
                    }
                ]
            });
          }


           //res.json("success log in ");
        }
 

        catch(err) {
            console.log(err);
        
            res.status(500).json({ err:err});
        }
    } 

)

//Registeration
router.post (
    "/register",
    body("Email").isEmail().withMessage("please enter a valid email "),
    body("Password").isLength({ min :8, max:20}).withMessage("password should be (8-20) character"),
    async (req , res) => {
        try {
           const errors = validationResult(req) ;
           if(!errors.isEmpty()){
              return res.status(400).json({errors:errors.array()});
           }

           const query = util.promisify(conn.query).bind(conn);
           const checkEmail = await query(
            "select * from user where email=?",
            [req.body.email]
           );
           if (checkEmail.length > 0){
            return res.status(400).json({
                errors: [
                    {
                        msgs : "email is already  exist"
                    }
                ]
            })
           }


           const UserData = {
            Name: req.body.Name,
            Email: req.body.Email,
            Phone: req.body.Phone, 
           
            Password: await bcrypt.hash(req.body.Password,10),
            token:crypto.randomBytes(16).toString("hex")
           };

 

           await query("insert into user set ?",UserData);
          // delete UserData.password;
           res.status(200).json(UserData);

           res.json("success");
        }
 

        catch(err) {
            console.log(err);
            res.status(500).json({ err:err});
        }
    } 

)
module.exports= router;