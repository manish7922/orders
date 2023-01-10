let users=[
    {
        id:1,
        name:"John",
        password:"john",
        role:"customer"
     
    },
    {
        id:2,
        name:"Sarah",
        password:"sarah",
        role:"customer"
    },
    {
        id:3,
        name:"George",
        password:"george",
        role:"customer"
   
    },
    {
        id:4,
        name:"Anna",
        password:"anna",
        role:"customer"
    },
    {
        id:5,
        name:"Tim",
        password:"tim",
        role:"admin"
     
    },
    {
        id:6,
        name:"Steve",
        password:"steve",
        role:"admin"
    },
]

let orders=[
    {orderId:1,userId:1,qty:10,value:55},
    {orderId:2,userId:2,qty:15,value:75},
    {orderId:3,userId:3,qty:20,value:20},
    {orderId:4,userId:1,qty:4,value:100},
    {orderId:5,userId:1,qty:6,value:72},
    {orderId:6,userId:2,qty:8,value:96},
    {orderId:7,userId:2,qty:12,value:240},
    {orderId:8,userId:1,qty:30,value:450},
]


module.exports={users,orders}