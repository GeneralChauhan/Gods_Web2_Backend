/* eslint-disable no-useless-escape */
const mongoose = require('mongoose');

const addNotice = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Please provide a Title of Article'],
    },
    companyName: {
        type: String,
        required: ['Please provide your company name'],
    },
    type: {
        type: String,
        trim:true,
    },
    CTC: {
        type: String
    },
    attachment: {
        type: String
    },
    description: {
        type: String,
        trim: true,
        required: [true, 'Please give description'],
    },
    createdAt: {
        type: Date,
        default: Date.now,
        trim:true,
    },
    
    tags:{
        type:[String],
    }
});

module.exports = mongoose.model('Notice', addNotice);