const express = require('express');
const {addNotice,getNotices,getNotice,getNoticesByTag,attachment} = require('./controller');

const router = express.Router();
router.route('/').post(addNotice).get(getNotices);
router.route('/tags').post(getNoticesByTag)
router.route('/getNotice').get(getNotice)
router.route('/attachment').post(attachment)



module.exports = router;