const ErrorResponse = require('../../util/errorResponse');
const asyncHandler = require('../../middleware/async');
const User = require('../user/model');


exports.register = asyncHandler(async (req, res, next)=>{
    const {fname,lname, email,year,branch,regid, password,username,role} = req.body;
    const preEmail = await User.findOne({email});
    const preReg = await User.findOne({regid});
    const x=req.body.regid;
    if(preEmail){
        return next(new ErrorResponse('Already registered with this email',400));
    }
    if(preReg){
        return next(new ErrorResponse('Already Registered with this Registration Number',401));
    }
    if(x.toString().length!=5){
        return next(new ErrorResponse('Wrong registration number',402));
    }
    const user = await User.create({fname,lname,branch,year,regid, email, password,username,role});

    sendTokenResponse(user, 200, res);

});

exports.login = asyncHandler(async (req, res, next) => {
    console.log(req.body);
    const {email, password,role} = req.body;
    

    if(!role){
        return next(new ErrorResponse('Please select a type',400));
    }
    // Validate email & password
    if (!email || !password) {
        return next(new ErrorResponse('Please provide an email and password', 400));
    }

    // Check for user
    const user = await User.findOne({email}).select('+password').select('+role').select('+fname').select('+branch').select('+regid');
    if (!user) {
        return next(new ErrorResponse('Invalid credentials', 400));
    }

    //  Check if type matches
    if(user.role!=role) {
        console.log(user.role);
        return next(new ErrorResponse('Invalid role',401));
    }
    // Check if password matches
    const isMatch = await user.matchPassword(password);
    

    if (!isMatch) {
        return next(new ErrorResponse('Invalid credentials', 402));
    }
    return res.status(200).json({
        success: true,
        user
    })
});

exports.logout = asyncHandler(async (req, res, next) => {
    res.cookie('token', 'none', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true,
    });

    res.status(200).json({
        success: true,
        data: {},
    });
});

exports.updatePassword = asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.user.id).select('+password');

    // Check current password
    if (!(await user.matchPassword(req.body.currentPassword))) {
        return next(new ErrorResponse('Password is incorrect', 401));
    }

    user.password = req.body.newPassword;
    await user.save();

    sendTokenResponse(user, 200, res);
});

// Get token from model, create cookie and send response
const sendTokenResponse = (user, statusCode, res) => {
    // Create token
    const token = user.getSignedJwtToken();
    const options = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
        httpOnly: true,
        secure: true
    };
    res.status(statusCode).cookie('token', token, options).json({success: true, token});
};
