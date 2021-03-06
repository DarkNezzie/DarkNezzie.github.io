const mysql = require("mysql");
const jwt = require('jsonwebtoken');
const bcrypt = require ('bcryptjs'); //hashing password


const db = mysql.createConnection({ //ip do servidor
    host: process.env.DATABASE_HOST,   
    user: process.env.DATABASE_USER,   
    password: process.env.DATABASE_PASSWORD,   
    database: process.env.DATABASE
});

exports.register = (req, res) => {
    console.log(req.body);

    const {name, email, password, passwordConfirm } = req.body; //destructuring 

    db.query('SELECT email FROM users WHERE email = ?', [email], async (error, results)=>{ //verificar se não existe um email igual
        if(error){ //mostrar o erro
            console.log(error);
        }
        if(results.length > 0){ //se existir um email igual
            return res.render('register', {
                message: 'That email is already in use.'
            })
        }else if( password !== passwordConfirm){ //se as pass não derem match
            return res.render('register', {
                message: 'The passwords do not match.'
            });
        }
        let hashedPassword = await bcrypt.hash(password, 8); //hashing password with 8 rounds
        console.log(hashedPassword);
        //Inserir User
        db.query('INSERT INTO users SET ?', {name:name, email:email, password:hashedPassword}, (error, results) =>{ 
            if(error){
                console.log(error);
            }else{
                console.log(results);
                return res.render('register', {
                    message: 'User Registered'
                });
            }
        })
    });
}


exports.login = async (req, res) => {

    try{
        const {email, password } = req.body; //destructuring 

        if(!email || !password){
            return res.status(400).render('login', {
                message: 'Não deixe campos em branco'
            })
        }
        
        db.query('SELECT * FROM users WHERE email = ?', [email], async(error,results)=>{
            //console.log(results);
            if(!results || !(await bcrypt.compare(password, results[0].password))){
                res.status(401).render('login',{ //forbidden code
                    message: 'O email ou a password estão errados'
                })

            }else{
                const id = results[0].id;
                //criar um token para o login (cookies)
                const token = jwt.sign({id:id}, process.env.JWT_SECRET, { //guardar no env
                    expiresIn: process.env.JWT_EXPIRES_IN
                });
                //console.log("TokenADDED: " + token);

                const cookieOptions = {
                    expires: new Date(
                        Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
                    ), 
                    httpOnly: true
                }
                res.cookie('jwt', token, cookieOptions); //set up the cookie
                res.status(200).redirect("/dashboard");
            }
        });

    }catch(error){
        console.log(error);
    }
}

exports.dashboard = (req, res) => {

    db.query('SELECT * FROM data', (error, results)=>{
       
        if(error){
            console.log(error);
        }
        
        //console.log(results);
        //const data = JSON.parse(JSON.stringify(results));
        //console.log(data);
        const data = "Hello";
        return res.render('dashboard', {data});
        
        //buildTable(data);
        

    });
    
}

exports.data = (req, res) => {

    db.query('SELECT * FROM data', (error, results)=>{
       
        if(error){
            console.log(error);
        }
        
        //console.log(results);
        const data = JSON.parse(JSON.stringify(results));
        //console.log(data);
        return res.json(data);
        

    });
    
}