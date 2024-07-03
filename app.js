document.addEventListener('DOMContentLoaded', () => {
    // Firebase configuration
    const firebaseConfig = {
      apiKey: "AIzaSyB6oRwWFUgFd8JRDWoE-cyD74R7how5Ogo",
      authDomain: "test-3c7a4.firebaseapp.com",
      projectId: "test-3c7a4",
      storageBucket: "test-3c7a4.appspot.com",
      messagingSenderId: "867223342645",
      appId: "1:867223342645:web:2f5577233e96435f036b7c",
      measurementId: "G-7HXJJ2R47G"
    };
  
    // Initialize Firebase
    try {
      firebase.initializeApp(firebaseConfig);
      console.log('Firebase initialized');
    } catch (error) {
      alert('Error initializing Firebase: ' + error.message);
      return;
    }
  
    // Check if Firebase modules are loaded
    if (typeof firebase === 'undefined' || !firebase.auth) {
      alert('Firebase SDK not loaded correctly.');
      return;
    }
  
    // Get elements
    const registerForm = document.getElementById('register-form');
    const loginForm = document.getElementById('login-form');
    const phoneAuthForm = document.getElementById('phone-auth-form');
    const userDetails = document.getElementById('user-details');
    const loginBtn = document.getElementById('login-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const userEmail = document.getElementById('user-email');
  
    // Login existing user
    loginBtn.addEventListener('click', () => {
      const email = document.getElementById('login-email').value;
      const password = document.getElementById('login-password').value;
      console.log('Login button clicked with email:', email);
  
      if (email === '' || password === '') {
        alert('Email and password cannot be empty');
        return;
      }
  
      firebase.auth().signInWithEmailAndPassword(email, password)
        .then(userCredential => {
          showUserDetails(userCredential.user);
        })
        .catch(error => {
          console.error('Error during login:', error);
          alert(error.message);
        });
    });
  
    // Logout user
    logoutBtn.addEventListener('click', () => {
      firebase.auth().signOut().then(() => {
        alert('Logged out!');
        userDetails.classList.add('hidden');
        loginForm.classList.remove('hidden');
      }).catch(error => {
        console.error('Error during logout:', error);
      });
    });
  
    // Show user details
    const showUserDetails = (user) => {
      userEmail.textContent = user.email || user.phoneNumber;
      userDetails.classList.remove('hidden');
      registerForm.classList.add('hidden');
      loginForm.classList.add('hidden');
      phoneAuthForm.classList.add('hidden');
    }; 
});