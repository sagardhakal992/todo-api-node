import {body} from "express-validator"
export const loginValidator=(req,res,next)=>{
    
    return [body('email').isEmail(),
    // password must be at least 5 chars long
    body('password').isLength({ min: 5 }),]
    
}