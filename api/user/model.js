const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userSchema = new mongoose.Schema({
    fname: {
        type: String,
        required: [true, 'Please provide your first name'],
    },
    lname: {
        type: String,
        required: [true, 'Please provide your last name'],
    },
    email: {
        type: String,
        required: [true, 'Please provide an email address'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/, 'Please add valid email address.'],
    },
    regid: {
        type: Number,
        unique: true,
        required: [true, 'Please provide your registration id'],
    },
    username: {
        type: String,
        required:[false],
        unique:false,
    },
    year: {
        type: String,
        enum: ['2nd year', '3rd year', '4th year','ME 2nd year'],
        required:[true, 'Please select your year'] 
    },
    branch: {
        type: String,
        enum: ['Comp','IT', 'ENTC','Mech'],
        required:[true, 'Please select your branch'] 
    },
    password: {
        type: String,
        required: [true, 'Password can not be blank'],
        select: false,
        minlength: 6,
    },
    role:{
        type:String,
        default:"student"
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastActive: {
        type: Date
    },
    resetPasswordToken: String,
    resetPasswordTokenExpire: Date,
});

// Encrypt password using bcrypt
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.getSignedJwtToken = function() {
    return jwt.sign({id: this._id}, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });
};

userSchema.methods.matchPassword = async function(enteredPassword) {
    // eslint-disable-next-line no-return-await
    return await bcrypt.compare(enteredPassword, this.password);
};
userSchema.methods.matchType = async function(enterdType){
    
}
module.exports = mongoose.model('User', userSchema);
