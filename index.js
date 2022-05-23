import { PrismaClient } from '@prisma/client'
import express from 'express';

import {validationResult,body} from "express-validator"
import { check } from "express-validator/src/middlewares/validation-chain-builders.js"
const app=express()
import * as argon from "argon2"
import jwt from 'jsonwebtoken'
import mutler from "multer"
import formidableMiddleware from 'express-formidable';
app.use(express.urlencoded({
    extended:true
}))
app.use( express.json({
    extended:true
}))

const prisma=new PrismaClient();

//sign up user
app.post("/signup",body("email").isEmail().withMessage("email field is required"),
check("password").isString().withMessage("password field is required").isLength({min:5}).withMessage("password must contain atleast 6 character")
,check("name").isLength({min:3}).withMessage("name required and must be 3character"),
async(req,res)=>{
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
        
        const role=await prisma.role.findFirst({where:{
            name:"superadmin"
        }})

        argon.hash(req.body.password,"ashdkjasdkjashdk").then(async(password)=>{
            const user=await prisma.user.create({
                data:{
                    email:req.body.email,
                    password:password,
                    name:req.body.name,
                    roleId:role.id,
                }
            })
            return res.status(201).json({user,});
        })   
    }
    catch(Err)
    {
        return res.status(400).json({Err,})
    }
    
})


//login user

app.post("/login",check("email").isString().withMessage("email field is requred").isEmail().withMessage("invalid email address"),check("password").isLength({min:5}).withMessage("too short 5 characters are required"),
async(req,res)=>{

    const errors=validationResult(req);
    if(!errors.isEmpty())
    {
        return res.status(400).json({error:{
            field:errors['errors'][0].param,
            param:errors['errors'][0].msg,
            other:errors['errors']
        }})
    }

    const user=await prisma.user.findFirst({where:{
        email:req.body.email
    },include:{role:true}})
    
    if(!user)
    {
       return res.status(404).json({error:{
            field:"user",
            param:"No user Found with given email"
        }})
    }

    argon.verify(user.password,req.body.password).then((value)=>{
        if(value)
        {
            delete user.password
            const token=jwt.sign({email:user.email,id:user.id},"myScretKey",{expiresIn:"1800s"})
            return res.json({user,token,})
        }
        return res.status(404).json({error:{
            field:"password",
            param:"Invalid Password"
        }})
    })
})
//get all role with authenticated user 
app.get("/getAllRoles",authenticateToken,async (req,res)=>{
    try{
        const roles=await prisma.role.findMany()
        return res.json(roles)
    }
    catch(err){
        return res.status(404).json({err,})
    }

})

//get one todo with id
app.post("/createTodo",[body("title").isString().withMessage("title field is required"),check("description").isString().withMessage("Description field is required")],
authenticateToken,async(req,res)=>{
    const error=validationResult(req);
    if(!error.isEmpty())
    {
        return res.status(404).json({error:{
            field:error['errors'][0].field,
            param:error['errors'][0].msg,
            other:error['errors']
        }})
    }
    try{
        
        if(req.file?.image)
        {
            
            const uploadingImage=mutler({storage:mutlerStorage}).single("image");
        }
        
        const data={
            title:req.body.title,
            description:req.body.description,
            userId:req.user.id,
            image:req.file?.path ?? null ,
            isCompleted:req.body.isCompleted ?? false
        }
        
        const todo=await prisma.todo.create({
            data,
            include:{
                createdBy:true
            }
        })
        delete todo.createdBy.password
        return res.status(201).json({todo,})
    }
    catch(err)
    {
        return res.status(400).json({err,})
    }

})

app.get("/getAllTodo",authenticateToken,async(req,res)=>{
    try{
        const roles=await prisma.todo.findMany({
            include:{
                createdBy:{
                    select:{
                        id:true,
                    name:true,
                    email:true,
                    role:true
                    }
                    
                },
            },
            
        })
        return res.json(roles)
    }
    catch(err){
        return res.status(404).json({err,})
    }
})

app.get("/getOneTodo/:id",authenticateToken,async(req,res)=>{
    try{
        const todo=await prisma.todo.findUnique({
            where:{
                id:req.params.id
            },
            include:{
                createdBy:{
                    select:{
                        id:true,
                    name:true,
                    email:true,
                    role:true
                    }
                    
                },
            },
        })
        if(!todo)
        {
            return res.status(404).json({error:{
                field:"todo",
                param:"No todo found with given id"
            }})
        }
        return res.json({todo,})
    }
    catch(err)
    {
        return res.error(err);
    }
})

//update todo app

app.post("/updateTodo/:id",[
    check("title").isString().withMessage("required"),
    check("description").isString().withMessage("required")
],[authenticateToken,authenticateTodo],async (req,res)=>{
  
    const error=validationResult(req)
    if(!error.isEmpty())
    {
        return res.status(400).json({error,})
    }

    try{
      const todo=  await prisma.todo.findUnique({
          where:{
              id:req.params.id
          }
      })
      if(!todo)
      {
          return res.status(404).json({err:"No todo found with given id"})
      }
      
      const data={
          title:req.body.title,
          description:req.body.description
      };
      
      todo=await prisma.todo.update({
          where:{
              id:todo.id
          },
          data,
      })

      return res.json({todo,})

    }
    catch(err)
    {
        return res.status(400).json({err,})
    }
})


//verify middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    
    if (token == null) return res.status(401).json({error:{field:"user",param:"not authenticated"}})
    
    jwt.verify(token, "myScretKey", async(err, user) => {
    if (err) return res.status(403).json({error:{field:"user",param:"not authenticated"}})
    user=await prisma.user.findFirst({where:{email:user.email},include:{role:true}})
    req.user=user;
      next()
    })
  }


//verify if the todo belongs to the user
async function authenticateTodo(req,res,next){
    
const todo=await prisma.todo.findUnique({where:{
        id:req.params.id,
    }})
    if(!todo)
    {
        return res.status(404).json({error:{
            field:"todo",
            param:"todo not found"
        }})
    }
    if(todo.userId !== req.user.id)
    {
      return res.status(403).json({error:{
          field:"todo",
          param:"You are not Authorized"
      }}) 
    }
    next();
}


const mutlerStorage=mutler.diskStorage({
    destination:(req,file,cb)=>{
        return cb(null,"./uploads");
    },
    filename:(req,file,cb)=>{
        cb(null,file.originalname);
    }
})


app.listen(5000)