// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyDhcgty5WymcpMdxZ46zIQu2aDZyjO7mMg",
  authDomain: "gods-84c1e.firebaseapp.com",
  projectId: "gods-84c1e",
  storageBucket: "gods-84c1e.appspot.com",
  messagingSenderId: "1027884093995",
  appId: "1:1027884093995:web:53cdf522b5ab366aeed06e",
  measurementId: "G-ZGH4TT57YN"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
console.log(analytics);