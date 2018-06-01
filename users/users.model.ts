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

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required:true,
        maxlength:80,
        minlength:3        
    },
    email:{
        type:String,
        unique: true,
        required:true,
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

/*É necessário usar function ao invés de arrow function
  pois o this pois caso contrário o this representará
  a função ao invés do documento ou query
*/
userSchema.pre('save',function(next){
  const user: User = this
  if(!user.isModified('password')){
    next()
  }else{
    //ele criptografa 10 vezes dificultando a quebra a senha
    bcrypt.hash(user.password,environment.security.saltRounds)
      .then(hash=>{
          user.password = hash
          next()
      })
  }
})

export const User = mongoose.model<User>('User',userSchema)
