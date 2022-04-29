const User = require('../models/User')

const bcrypt = require('bcryptjs')


module.exports = class AuthController{
    static login(req,res){
        res.render('auth/login')
    }
    static register(req,res){
            res.render('auth/register')
    }
    //login
    static async loginPost(req,res){
        const {email,password} = req.body

        // se o usuario existe
        const user = await User.findOne({ where: {email: email}})

        if(!user){
            req.flash('message', 'Usuário não encontrado!')
            res.render('auth/login')

            return
        }

        //validação da senha digitada com a do banco de dados
        const passwordMatch = bcrypt.compareSync(password, user.password)
        if(!passwordMatch){
            req.flash('message', 'Senha invalida!')
            res.render('auth/login')

            return
        }
        req.session.userid = user.id

        req.flash('message', 'Login efetuado com sucessso!')
        
        req.session.save(()=>{
            res.redirect('/')
        })
    }


    //logout
     static logout(req,res){
         req.session.destroy()
           res.redirect('/login') 
    }

    static async registerPost(req,res){
        const {name, email, password, confirmpassword} = req.body
        //validação se senha
        if(password != confirmpassword){
            //mensagem
            req.flash('message', 'As senhas não conferem, tente novamente!')
            res.render('auth/register')
            return
        }
        //check se o usuario existe

        const checkifUserExists = await User.findOne({where: {email:email}})

        if(checkifUserExists){
            req.flash('message', 'O e-mail já esta em uso!')
            res.render('auth/register')

            return
        }
       
        //criando a senha
        const salt = bcrypt.genSaltSync(10)
        const hashedPassword = bcrypt.hashSync(password,salt)

        const user = {
            name,
            email,
            password: hashedPassword
        }
        try{
            const createdUser = await User.create(user)
            //inicializa sessão
            req.session.userid = createdUser.id

            req.flash('message', 'Cadastro realizado com sucessso!')
            
            req.session.save(()=>{
                res.redirect('/')
            })
       
        }catch(err){
            console.log(err)
        }
    }
}
