// backend/firebase.js

const admin = require('firebase-admin');
const serviceAccount = require('./firebaseKey.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://resume-buliding-576b4.firebaseio.com"
});

module.exports = admin;

