const ErrorResponse = require('../../util/errorResponse');
const asyncHandler = require('../../middleware/async');
const Notice = require('./model');
// const multer = require('multer');
 const path = require('path');


exports.attachment = asyncHandler(async(req,res,next)=>{
  if(req.files){
  const file = req.files[''];
  file.name = file.name + Date.now();
  file.mv(`./public/uploads/${file.name}`, async err => {
    if(err){
      console.error(err);
      return next(
        new ErrorResponse('Problem with file upload',500));
    }
  })
  return res.status(200).json({
    success: true,
    message: `File added successfully`,
    
    })
  }
});

  



// @route: /api/v1/notice
// @req-type: POST
// @description: Add new Notice
exports.addNotice = asyncHandler(async(req, res, next) =>{
  if(req.files){
  const file = req.files[''];
  file.name = req.body.companyName+ Date.now()+".pdf";
  file.mv(`./public/uploads/${file.name}`, async err => {
    if(err){
      console.error(err);
      return next(
        new ErrorResponse('Problem with file upload',500));
    }
  })}
  // return res.status(200).json({
  //   success: true,
  //   message: `File added successfully`,
    
  //   })

  const body ={
      title: req.body.title,
      companyName: req.body.companyName,
      type: req.body.type,
      description: req.body.description,
      tags: req.body.tags,
      if(file){
        attachment:file.name
      }
  }  
  
const notice = await Notice.create(body);
return res.status(200).json({
    success: true,
    message: `Notice added successfully`
    })

});


// @route: /api/v1/notice
// @req-type: GET
// @description: get all notice

exports.getNotices = asyncHandler(async(req,res,next)=>{
    const notices = await Notice.find({}).sort({_id:-1}).limit(30);
    return res.status(200).json({
        success: true,
        count: notices.length,
        notices
    })
});

//@route:
// @req-type: GET
// @description : Get notice by title
exports.getNotice = asyncHandler(async(req, res, next)=>{
    const notice = await Notice.find({title: req.params.title});
    return res.status(200).json({
        success: true,
        notice
    });
});


exports.getNoticesByTag = asyncHandler(async (req, res, next) => {
    const tags = req.body.tags
    const notice = await Notice.find({ $and: [{}, { articleTags: { $in: tags } }] });
    return res.status(200).json({
        success: true,
        notice
    });
});

