var express = require("express");
let jwt=require("jsonwebtoken");
let passport=require("passport");
let JwtStrategy=require("passport-jwt").Strategy
let ExtarctJWT=require("passport-jwt").ExtractJwt
// let cookieParser=require("cookie-parser");
let {users,orders}=require("./dataToken");



var app = express();
app.use(express.json());
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept,Authorization"
  );
//   res.header("Access-Control-Expose-Headers","Authorization")
res.header("Access-Control-Expose-Headers","X-Auth-Token")
  res.header("Access-Control-Allow-Methods", "PUT, POST, GET, DELETE, OPTIONS");
  next();
});
const port =process.env.PORT || 2411;
app.use(passport.initialize());
const params={
    jwtFromRequest:ExtarctJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey:"jwtsecret23455785452",
}

const jwtExpirySecond=30;

let strategyALL=new JwtStrategy(params,function(token,done){
    console.log("In JWTStrategy--All",token);
    let user=users.find(u=>u.id===token.id);

    console.log("user",user);
    if(!user){
      return done(null,false, {message:"Incorrect username and password"});
    }
    else{
      return done(null,user);
    }
  });

  let strategyAdmin=new JwtStrategy(params,function(token,done){
    console.log("In JWTStrategy-Admin",token);
    let user=users.find(u=>u.id===token.id);

    console.log("user",user);
    if(!user){
      return done(null,false, {message:"Incorrect username and password"});
    }
    else if(user.role!=="admin"){
        return done(null,false,{message:"you do not have admin role"})
      }
    else{
      return done(null,user);
    }
  });



passport.use("roleAll",strategyALL);
passport.use("roleAdmin",strategyAdmin);


app.post("/user",function(req,res){
    let {username,password}=req.body;
    console.log(username,password);
    let user=users.find((u)=>u.name===username && u.password===password);
    console.log();
    if(user){
      
      let payload={id:user.id}
      let token=jwt.sign(payload,params.secretOrKey,{
        algorithm:"HS256",
        expiresIn:jwtExpirySecond,
      })

    //   res.cookie(myCookie,payload)
    //   res.send({token:"bearer  "+token});
    // res.setHeader("Authorization",token)
    // res.setHeader("X-Auth-Token",token)
    res.send(token);
    }
    else 
    res.sendStatus(401);
  })


  
app.get("/user",passport.authenticate("roleAll",{session:false}),function(req,res){
    console.log("IN GET /user",req.user);
    res.send(req.user);
  });
  
  app.get("/myOrders",passport.authenticate("roleAll",{session:false}),function(req,res){
    console.log("IN GET /myOrders",req.user);
    let orders1=orders.filter(ord=>ord.userId===req.user.id);
    res.send(orders1)
  })
  
  app.get("/allOrders",passport.authenticate("roleAdmin",{session:false}),function(req,res){
    console.log("IN GET /allOrder",req.user);
    // let orders1=orders.filter(ord=>ord.userId===req.user.id);
    res.send(orders) 
  })




app.listen(port, () => console.log(`Node APP Listening on ${port}!`));