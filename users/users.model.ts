import * as mongoose from 'mongoose'
import { StringDecoder } from 'string_decoder';
import {validateCPF} from '../common/validators'
import * as bcrypt from  'bcrypt'
import {environment} from '../common/environment'


export interface User extends mongoose.Document{
    name:string,
    email:string,
    password:string
}

export interface UserModel extends  mongoose.Model<User>{
    findByEmail(email:string):Promise<User>   
}


const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required:true,
        maxlength:80,
        minlength:3        
    },
    email:{
        type:String,
        //unique: true,
        required:true//,
        //match:/^[a-z0-9.]+@[a-z0-9]+\.[a-z]+\.([a-z]+)?$/
    },
    password:{
        type: String,
        select: false,
        required:true
    },
    gender:{
        type:String,
        required: false,
        enum:['Male','Female']
    },
    cpf:{
        type:String,
        required:false,
        validate:{
            validator:validateCPF,
            message:'{PATH}:Invalid CPF({VALUE})'
        }
    }
})

userSchema.statics.findByEmail = function(email: string){
    return this.findOne({email})
}


const hashPassword = (obj, next) => {
    //ele criptografa 10 vezes dificultando a quebra a senha
    bcrypt.hash(obj.password,environment.security.saltRounds)
      .then(hash=>{
          obj.password = hash
          next()
      })
}


/*É necessário usar function ao invés de arrow function
  pois o this pois caso contrário o this representará
  a função ao invés do documento ou query
*/
const saveMiddleware = function(next){
    const user: User = this
    if(!user.isModified('password')){
      next()
    }else{
      hashPassword(user, next)
    }
  }

const updateMiddleware = function(next){
    if(!this.getUpdate().password){
      next()
    }else{
        hashPassword(this.getUpdate(), next)
    }
  }

userSchema.pre('save',saveMiddleware)
userSchema.pre('findOneAndUpdate',updateMiddleware)
userSchema.pre('update',updateMiddleware)

export const User = mongoose.model<User,UserModel>('User',userSchema)