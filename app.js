const express = require('express'); 
const { Pool } = require('pg'); 
const bodyParser = require('body-parser'); 
const bcrypt = require('bcrypt'); 

const app = express(); 
const port = 3000; 

const pool = new Pool({ 
   user: 'postgres', 
   host: 'localhost', 
   database: 'postgres', 
   password: '1908', 
   port: 5432, 
  }); 


app.use(bodyParser.urlencoded({ extended: true })); 
app.use(bodyParser.json());

//--Role Authorization Middleware---
const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.user && req.user.role === role) {
      return next();
    } else if (req.admin && req.admin.role === role) {
      return next();
    } else if (req.moderator && req.moderator.role === role) {
      return next();
    } else {
      return res.status(403).json({message: "Unauthorized"});
    }
  };
};

app.use((req, res, next) => {
  req.user = {role: "user"};
  next();
});



app.use((req, res, next) => {
  req.admin = {role: "admin"};
  next();
}); 

app.use((req, res, next) => {
  req.moderator = {role: "moderator"};
  next();
});

//-----Admin Routes-------

app.get('/admin', authorizeRole("admin"), (req, res) => { 
  res.sendFile(__dirname + '/admin_page.html'); 
});

//-----Moderator Routes-----

app.get('/moderator', authorizeRole("moderator"), (req, res) => { 
  res.sendFile(__dirname + '/moderator_page.html'); 
});

//------User Routes-------

app.get('/user', authorizeRole("user"), (req, res) => { 
  res.sendFile(__dirname + '/user_page.html');
});


//-----Sign Up------

app.get('/', (req, res) => { 
  res.sendFile(__dirname + '/index.html'); 
});

app.post('/api/auth/signup', async (req, res) => { 
   const { username, email, password, role } = req.body; 
   
// Hash the password 

const hashedPassword = await bcrypt.hash(password, 10); 

// Insert user into the database 

try {
   // Check if the username or email already exists
   const userCheck = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);

    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    // Insert user into the database
    const result = await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *',
      [username, email, hashedPassword, role]
    );
    res.redirect('/signIn');
}catch (error) {
   console.error(error);
   res.status(500).send('Error registering user');
 }
}); 

//-----Sign In------

app.get('/signIn', (req, res) => { 
  res.sendFile(__dirname + '/signIn.html'); 
}); 

app.post('/api/auth/signin', async (req, res) => { 
  const { username, password } = req.body; 

try {
   const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

   if (result.rows.length === 1) {
     const user = result.rows[0];
     const passwordMatch = await bcrypt.compare(password, user.password);

     if (passwordMatch) {
       if (user.role === 'admin') {
         res.redirect('/admin');
       } else if (user.role === 'moderator') {
         res.redirect('/moderator');
       } else {
         res.redirect('/user');
       }
     }else {
       res.status(401).json({ message: 'Invalid password' });
     }
   } else {
     res.status(404).json({ message: 'User not found' });
   }
 } catch (error) {
   console.error(error);
   res.status(500).send('Error during login');
 }
});

//----Admin's Button Add User--------

app.post('/admin/addUser', authorizeRole("admin"),async(req, res) => {
  try {
    const { username, email, password, role} = req.body;

    const hashedPassword = await bcrypt.hash(password,10);

    // Insert user into the database
    const result = await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *',
      [username, email, hashedPassword, role]
    );

    res.status(201).json({message: 'User added successfully', user: result.rows[0] });
  }catch (error) {
    console.error(error);
    res.status(500).json({message: 'Error adding user to the database' });
  }
});

//----Admin's Button Delete User--------

app.delete('/api/admin/deleteuser', async (req, res) => {
  try {
    const { userIdToDelete } = req.body;
    const query = 'DELETE FROM users WHERE id = $1 RETURNING *';
    const values = [userIdToDelete];

    const result = await pool.query(query, values);

    res.status(200).json({ message: 'User deleted successfully', user: result.rows[0] });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

//----Moderator's Button Edit Content----


//----Log Out------
app.get('/logOut', (req, res) => { 
  res.sendFile(__dirname + '/signIn.html'); 
});


app.listen(port, () => { 
  console.log(`Server is running on http://localhost:${port}`);
}); 