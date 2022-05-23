import express,{Router} from "express"
import {PrismaClient} from "@prisma/client"
import { loginValidator } from "../middleware/validation/login.js"
import {validationResult,body} from "express-validator"
import { check } from "express-validator/src/middlewares/validation-chain-builders.js"
import * as argon from 'argon2'
const router=Router()
const prisma=new PrismaClient()
router.get("/",(req,res)=>{
    res.json("hii");
})
router.use(express.json())

router.post("/signup",body("email").isEmail().withMessage("email field is required"),
check("password").isString().withMessage("password field is required").isLength({min:5}).withMessage("password must contain atleast 6 character")
,check("name").isLength({min:3}).withMessage("name required and must be 3character"),
async(req,res)=>{
    console.log(req.body);
    const errors=validationResult(req)
    if(!errors.isEmpty())
    {
        
        return res.status(400).json({error:{
            field:errors['errors'][0].param,
            param:errors['errors'][0].msg,
            other:errors['errors']
        }})
    }
    
    try{
        const password=await argon.hash(req.body.password)
        const user=await prisma.user.create({
            data:{
                name:req.body.user,
                password:password,
                name:req.body.name
            }
        })
        return res.status(201).json({user,});
    }
    catch(Err)
    {
        return res.status(400).json({Err,})
    }
    
})

export default router