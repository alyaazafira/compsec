const express = require('express');
const mongodb = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();
const port = process.env.PORT || 3000;
const secretKey = 'officevisitor';

// MongoDB connection URL
const mongoURL =
  'mongodb+srv://alyaazafira:4pp0intmentv1s170r@alyaa.emy970i.mongodb.net/?retryWrites=true&w=majority';

// MongoDB database and collections names
const dbName = 'companyappointment';
const adminCollection = 'admin';
const staffCollection = 'staff';
const securityCollection = 'security';
const appointmentCollection = 'appointments';
const testCollection = 'test';

// Middleware for parsing JSON data
app.use(express.json());

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'VMS appointment',
            version: '1.0.0',
        },
    },
    apis: ['./index.js'],
};
const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// MongoDB connection
//mongodb.MongoClient.connect(mongoURL, { useUnifiedTopology: true })
mongodb.MongoClient.connect(mongoURL)
  .then((client) => {
    const db = client.db(dbName);
    const adminDB = db.collection(adminCollection);
    const staffDB = db.collection(staffCollection);
    const securityDB = db.collection(securityCollection);
    const appointmentDB = db.collection(appointmentCollection);
    const testDB = db.collection(testCollection);

// Middleware for authentication and authorization (specifically for security role)
const authenticateTokenForSecurity = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err || user.role !== 'security') {
      return res.status(403).json({ error: 'Invalid or unauthorized token' });
    }
    req.user = user;
    next();
  });
};
// Middleware for authentication and authorization (specifically for admin role)
const authenticateTokenForAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err || user.role !== 'admin') {
      return res.status(403).json({ error: 'Invalid or unauthorized token' });
    }
    req.user = user;
    next();
  });
};

/**
* @swagger
* components:
*   securitySchemes:
*     BearerAuth:
*       type: http
*       scheme: bearer
*       bearerFormat: JWT
*/
 
/**
 * @swagger
 * tags:
 *   name: admin
 *   description: APIs for admin
 */

 /**
 * @swagger
 * tags:
 *   name: security
 *   description: APIs for security personnel
 */

/**
 * @swagger
 * tags:
 *   name: staff
 *   description: APIs for staff 
 */

/**
 * @swagger
 * tags:
 *   name: visitor 
 *   description: APIs for visitor 
 */
//register admin
/**
 * @swagger
 * /register-admin:
 *   post:
 *     summary: Register a new admin
 *     tags: [admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username for the new admin.
 *               password:
 *                 type: string
 *                 description: The password for the new admin.
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '201':
 *         description: Successfully registered a new admin.
 *       '400':
 *         description: Bad request, username already exists.
 *       '500':
 *         description: Internal Server Error.
 */
app.post('/register-admin', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if the username already exists for admin
    const existingAdmin = await db.collection('admin').findOne({ username });

    if (existingAdmin) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new admin
    const newAdmin = {
      username,
      password: hashedPassword,
    };

    // Insert the new admin into the "admin" collection of "companyappointment" database
    await db.collection('admin').insertOne(newAdmin);

    res.status(201).json({ message: 'Successfully registered a new admin' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

//login admin

/**
 * @swagger
 * /login-admin:
 *   post:
 *     summary: Admin Login
 *     description: Authenticate admin with username and password
 *     tags: [admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       '401':
 *         description: Unauthorized - Invalid credentials
 *       '500':
 *         description: Internal Server Error - Error storing token
 */
app.post('/login-admin', async (req, res) => {
  const { username, password } = req.body;

  const admin = await db.collection('admin').findOne({ username });

  if (!admin) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(password, admin.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid credentials');
  }

  // Generate a new token for the admin
  const newToken = jwt.sign({ username, role: 'admin' }, secretKey);

  // Update the admin's token in the database
  db.collection('admin')
    .updateOne({ username }, { $set: { token: newToken } })
    .then(() => {
      res.status(200).json({ token: newToken });
    })
    .catch(() => {
      res.status(500).send('Error storing token');
    });
});

//admin can see everythings
/**
 * @swagger
 * /admin/see-everything:
 *   get:
 *     summary: View all information (staff, security, and appointments)
 *     tags: [admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Successfully retrieved all information.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 staff:
 *                   type: array
 *                   description: List of staff members.
 *                   items:
 *                     type: object
 *                     properties:
 *                       // Define staff properties here
 *                 security:
 *                   type: array
 *                   description: List of security details.
 *                   items:
 *                     type: object
 *                     properties:
 *                       // Define security properties here
 *                 appointments:
 *                   type: array
 *                   description: List of appointments.
 *                   items:
 *                     type: object
 *                     properties:
 *                       // Define appointment properties here
 *       '401':
 *         description: Unauthorized - Invalid or missing token.
 *       '403':
 *         description: Forbidden - User does not have admin privileges.
 *       '500':
 *         description: Internal Server Error.
 */
app.get('/admin/see-everything', authenticateTokenForAdmin, async (req, res) => {
  try {
    // Retrieve all staff members
    const staff = await db.collection('staff').find().toArray();

    // Retrieve all security details
    const security = await db.collection('security').find().toArray();

    // Retrieve all appointments
    const appointments = await db.collection('appointments').find().toArray();

    res.status(200).json({ staff, security, appointments });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

//admin see data
/**
 * @swagger
 * /admin/data:
 *   get:
 *     summary: Get all data for admin
 *     description: Retrieve all data including staff, security, and appointment information.
 *     tags: [admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Successfully retrieved all data for admin.
 *       '401':
 *         description: Unauthorized - Invalid or missing token.
 *       '403':
 *         description: Forbidden - User does not have admin privileges.
 *       '500':
 *         description: Internal Server Error.
 */
app.get('/admin/data', authenticateTokenForAdmin, async (req, res) => {
  try {
    // Fetch all data from staff, security, and appointment collections
    const staffData = await db.collection('staff').find({}).toArray();
    const securityData = await db.collection('security').find({}).toArray();
    const appointmentData = await db.collection('appointment').find({}).toArray();

    const allData = {
      staff: staffData,
      security: securityData,
      appointment: appointmentData,
    };

    res.status(200).json(allData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// Register Staff
/**
 * @swagger
 * /register-staff:
 *   post:
 *     summary: Register a new staff (Security Authorization Required).
 *     tags:
 *       - security
 *     security:
 *       - BearerAuth: []  # Use the correct security scheme name
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               staffId:
 *                 type: number
 *                 description: The unique identifier for the new staff member.
 *               name:
 *                 type: string
 *                 description: The name of the new staff member.
 *               username:
 *                 type: string
 *                 description: The username for the new staff member.
 *               password:
 *                 type: string
 *                 description: The password for the new staff member.
 *               position:
 *                 type: string
 *                 description: The position of the new staff member.
 *               phoneNumber:
 *                 type: string
 *                 description: The phone number of the new staff member.
 *             required:
 *               - staffId
 *               - name
 *               - username
 *               - password
 *               - position
 *               - phoneNumber
 *     responses:
 *       '201':
 *         description: Successfully registered a new staff member.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *       '400':
 *         description: Bad request, username already exists.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *       '401':
 *         description: Unauthorized, invalid security token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid security token
 *       '403':
 *         description: Forbidden, only security can register new staff.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Permission denied
 *       '500':
 *         description: Internal Server Error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Internal Server Error
 */
app.post('/register-staff', authenticateTokenForSecurity, async (req, res) => {
  const { role } = req.user;

  if (role !== 'security') {
    return res.status(403).json({ error: 'Permission denied' });
  }

  const { staffId, name, username, password, position, phoneNumber } = req.body;

  try {
    // Check if the username already exists
    const existingStaff = await staffDB.findOne({ username });

    if (existingStaff) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new staff member
    const newStaff = {
      staffId,
      name,
      username,
      password: hashedPassword,
      position,
      phoneNumber,
    };

    // Update the staff member with the token
    const result = await staffDB.insertOne(newStaff);

    // Use the correct security scheme name in the token generation
    const token = jwt.sign({ username, role: 'staff' }, `${secretKey}-${Date.now()}`);

    // Update the staff member with the token
    await staffDB.updateOne({ _id: result.insertedId }, { $set: { token } });

    res.status(201).json({ message: 'Successfully registered a new staff member' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

    // Staff login
/**
 * @swagger
 * /login-staff:
 *   post:
 *     summary: Login for Staff
 *     description: Login with username and password
 *     tags:
 *       - staff
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       '400':
 *         description: Invalid request body
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid credentials
 *       '500':
 *         description: Internal Server Error - Error storing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Error storing token
 */
app.post('/login-staff', async (req, res) => {
  const { username, password } = req.body;

  const staff = await staffDB.findOne({ username });

  if (!staff) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(password, staff.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid credentials');
  }

  const token = jwt.sign({ username, role: 'staff' }, secretKey);
  staffDB
    .updateOne({ username }, { $set: { token } })
    .then(() => {
      res.status(200).json({ token });
    })
    .catch(() => {
      res.status(500).send('Error storing token');
    });
});

/**
 * @swagger
 * /register-security:
 *   post:
 *     summary: Register a new security member
 *     tags: [security]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the security member
 *               password:
 *                 type: string
 *                 description: The password of the security member
 *     responses:
 *       201:
 *         description: Successfully registered
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: The JWT token for the registered security member
 *       400:
 *         description: Bad Request
 *       500:
 *         description: Internal Server Error
 */
app.post('/register-security', async (req, res) => {
    try {
      const { username, password } = req.body;
  
      // Check if the username already exists
      const existingSecurity = await securityDB.findOne({ username });
      if (existingSecurity) {
        return res.status(400).json({ error: 'Username already exists' });
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create a new security member
      const newSecurity = await securityDB.insertOne({
        username,
        password: hashedPassword,
      });
  
      // Generate JWT token
      const token = jwt.sign({ username, role: 'security' }, secretKey);
  
      // Update the security member with the token
      await securityDB.updateOne({ username }, { $set: { token } });
  
      res.status(201).json({ message: 'Successfully registered a new staff member' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  

// Security login
/**
 * @swagger
 * /login-security:
 *   post:
 *     summary: Security Login
 *     description: Authenticate security with username and password
 *     tags: [security]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       '401':
 *         description: Unauthorized - Invalid credentials
 *       '500':
 *         description: Internal Server Error - Error storing token
 */

app.post('/login-security', async (req, res) => {
  const { username, password } = req.body;

  const security = await securityDB.findOne({ username });

  if (!security) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(password, security.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid credentials');
  }

  // Generate a new token for the user
  const newToken = jwt.sign({ username, role: 'security' }, secretKey);

  // Update the user's token in the database
  securityDB
    .updateOne({ username }, { $set: { token: newToken } })
    .then(() => {
      res.status(200).json({ token: newToken });
    })
    .catch(() => {
      res.status(500).send('Error storing token');
    });
});

// Middleware for authentication and authorization
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send('Missing token');
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid or expired token');
    }
    req.user = user;
    next();
  });
};

/**
 * @swagger
 * /change-password:
 *   post:
 *     summary: Change Password
 *     description: Change user password by verifying the old password
 *     tags:
 *       - authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [security, staff]
 *               oldPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Password changed successfully
 *       '400':
 *         description: Invalid request body or old password mismatch
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid request body or old password mismatch
 *       '401':
 *         description: Unauthorized - Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid credentials
 *       '500':
 *         description: Internal Server Error - Error updating password
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Error updating password
 */
app.post('/change-password', async (req, res) => {
  const { username, role, oldPassword, newPassword } = req.body;

  let user;
  if (role === 'security') {
    user = await securityDB.findOne({ username });
  } else if (role === 'staff') {
    user = await staffDB.findOne({ username });
  } else {
    return res.status(400).send('Invalid role');
  }

  if (!user) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(oldPassword, user.password);

  if (!passwordMatch) {
    return res.status(400).send('Invalid request body or old password mismatch');
  }

  const hashedNewPassword = await bcrypt.hash(newPassword, 10);

  if (role === 'security') {
    securityDB
      .updateOne({ username }, { $set: { password: hashedNewPassword } })
      .then(() => {
        res.status(200).send('Password changed successfully');
      })
      .catch(() => {
        res.status(500).send('Error updating password');
      });
  } else if (role === 'staff') {
    staffDB
      .updateOne({ username }, { $set: { password: hashedNewPassword } })
      .then(() => {
        res.status(200).send('Password changed successfully');
      })
      .catch(() => {
        res.status(500).send('Error updating password');
      });
  }
});

//create visitor appointment
/**
 * @swagger
 * /appointments:
 *   post:
 *     summary: Create Appointment.
 *     description: Create a new appointment without requiring security authorization.
 *     tags:
 *       - visitor
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - company
 *               - purpose
 *               - phoneNo
 *               - date
 *               - time
 *               - verification
 *               - staff
 *             properties:
 *               name:
 *                 type: string
 *               company:
 *                 type: string
 *               purpose:
 *                 type: string
 *               phoneNo:
 *                 type: string
 *               date:
 *                 type: string
 *               time:
 *                 type: string
 *               verification:
 *                 type: boolean
 *               staff:
 *                 type: object
 *                 required:
 *                   - staffId
 *                 properties:
 *                   staffId:
 *                     type: number
 *     responses:
 *       '200':
 *         description: Appointment created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *       '400':
 *         description: Bad request - Invalid input data or staffId not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Bad request - Invalid input data
 *       '500':
 *         description: Internal Server Error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Internal Server Error
 */
app.post('/appointments', async (req, res) => {
  const {
    name,
    company,
    purpose,
    phoneNo,
    date,
    time,
    verification,
    staff: { staffId },
  } = req.body;

  try {
    // Additional validation 
    if (!name || !company || !purpose || !phoneNo || !date || !time || verification === undefined || !staffId) {
      return res.status(400).json({ error: 'Bad request - Invalid input data' });
    }

    // Fetch the staff based on staffId
    const staff = await staffDB.findOne({ staffId });

    if (!staff) {
      return res.status(400).json({ error: 'Bad request - Invalid staffId or staff not found' });
    }

    const appointment = {
      name,
      company,
      purpose,
      phoneNo,
      date,
      time,
      verification,
      staff: { staffId },
    };

    // Perform the database operation (consider using transactions)
    await appointmentDB.insertOne(appointment);

    res.status(200).json({ message: 'Appointment created successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: `Error creating appointment: ${error.message}` });
  }
});


    // Get staff's appointments
/**
 * @swagger
 * /staff-appointments/{username}:
 *   get:
 *     summary: Get Staff Appointments
 *     description: Retrieve appointments for a specific staff member
 *     tags:
 *       - staff
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: username
 *         description: Username of the staff member
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Appointments retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   name:
 *                     type: string
 *                   company:
 *                     type: string
 *                   purpose:
 *                     type: string
 *                   phoneNo:
 *                     type: string
 *                   date:
 *                     type: string
 *                     format: date
 *                   time:
 *                     type: string
 *                   verification:
 *                     type: boolean
 *                   staff:
 *                     type: object
 *                     properties:
 *                       username:
 *                         type: string
 *       '403':
 *         description: Forbidden - Invalid or unauthorized token
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: Invalid or unauthorized token
 *       '500':
 *         description: Internal Server Error - Error retrieving appointments
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: Error retrieving appointments
 */

    app.get('/staff-appointments/:username', authenticateToken, async (req, res) => {
      const { username } = req.params;
      const { role } = req.user;
    
      if (role !== 'staff') {
        return res.status(403).send('Invalid or unauthorized token');
      }
    
      appointmentDB
        .find({ 'staff.username': username })
        .toArray()
        .then((appointments) => {
          res.json(appointments);
        })
        .catch((error) => {
          res.status(500).send('Error retrieving appointments');
        });
    });

// Update appointment verification by visitor name

/**
 * @swagger
 * /appointments/{name}:
 *   put:
 *     summary: Update Appointment Verification
 *     description: Update the verification status of an appointment by name
 *     tags: 
 *        - staff
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: name
 *         required: true
 *         description: Name of the appointment to be updated
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               verification:
 *                 type: boolean
 *     responses:
 *       '200':
 *         description: Appointment verification updated successfully
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '500':
 *         description: Internal Server Error - Error updating appointment verification
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '403':
 *         description: Forbidden - Invalid or unauthorized token
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '401':
 *         description: Unauthorized - Missing token
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 */

app.put('/appointments/:name', authenticateToken, async (req, res) => {
  const { name } = req.params;
  const { verification } = req.body;
  const { role } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  appointmentDB
    .updateOne({ name }, { $set: { verification } })
    .then(() => {
      res.status(200).send('Appointment verification updated successfully');
    })
    .catch((error) => {
      res.status(500).send('Error updating appointment verification');
    });
});

    // Delete appointment
/**
 * @swagger
 * /appointments/{name}:
 *   delete:
 *     summary: Delete Appointment
 *     description: Delete an appointment by name
 *     tags: [staff]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: name
 *         required: true
 *         description: Name of the appointment to be deleted
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Appointment deleted successfully
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '500':
 *         description: Internal Server Error - Error deleting appointment
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '403':
 *         description: Forbidden - Invalid or unauthorized token
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '401':
 *         description: Unauthorized - Missing token
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 */

    app.delete('/appointments/:name', authenticateToken, async (req, res) => {
      const { name } = req.params;
      const { role } = req.user;
    
      if (role !== 'staff') {
        return res.status(403).send('Invalid or unauthorized token');
      }
    
      appointmentDB
        .deleteOne({ name })
        .then(() => {
          res.status(200).send('Appointment deleted successfully');
        })
        .catch((error) => {
          res.status(500).send('Error deleting appointment');
        });
    });

// Get all appointments (for security)
/**
 * @swagger
 * /appointments:
 *   get:
 *     summary: Get Appointments (for security)
 *     description: Retrieve appointments based on an optional name filter, accessible only by security personnel
 *     tags:
 *       - security
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: name
 *         description: Filter appointments by name (case-insensitive)
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Appointments retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   name:
 *                     type: string
 *                   date:
 *                     type: string
 *                     format: date
 *                   time:
 *                     type: string
 *                   staff:
 *                     type: object
 *                     properties:
 *                       username:
 *                         type: string
 *                   verification:
 *                     type: boolean
 *       '403':
 *         description: Forbidden - Invalid or unauthorized token
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: Invalid or unauthorized token
 *       '500':
 *         description: Internal Server Error - Error retrieving appointments
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: Error retrieving appointments
 */
app.get('/appointments', authenticateTokenForSecurity, async (req, res) => {
  const { name } = req.query;
  const { role } = req.user;

  if (role !== 'security') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  const filter = name ? { name: { $regex: name, $options: 'i' } } : {};

  appointmentDB
    .find(filter)
    .project({ name: 1, date: 1, time: 1, 'staff.username': 1, verification: 1 }) // Include only necessary fields
    .toArray()
    .then((appointments) => {
      res.json(appointments);
    })
    .catch((error) => {
      res.status(500).send('Error retrieving appointments');
    });
});



// Logout

/**
 * @swagger
 * /logout:
 *   post:
 *     summary: User Logout
 *     description: Logout the user and invalidate the token
 *     tags:
 *      - security
 *      - staff
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *      content:
 *        application/json:
 *        schema:
 *        type: object
 *        properties:
 *          //Request body properties here
 *     responses:
 *       '200':
 *         description: Logged out successfully
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '500':
 *         description: Internal Server Error - Error logging out
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '403':
 *         description: Forbidden - Invalid or unauthorized token
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '401':
 *         description: Unauthorized - Missing token
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '404':
 *         description: Not Found - Invalid role
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 */

app.post('/logout', authenticateToken, async (req, res) => {
    const { role } = req.user;
  
    // Depending on the role (staff or security), update the corresponding collection (staffDB or securityDB)
    if (role === 'staff') {
      staffDB
        .updateOne({ username: req.user.username }, { $unset: { token: 1 } })
        .then(() => {
          res.status(200).send('Logged out successfully');
        })
        .catch(() => {
          res.status(500).send('Error logging out');
        });
    } else if (role === 'security') {
      securityDB
        .updateOne({ username: req.user.username }, { $unset: { token: 1 } })
        .then(() => {
          res.status(200).send('Logged out successfully');
        })
        .catch(() => {
          res.status(500).send('Error logging out');
        });
    } else {
      res.status(500).send('Invalid role');
    }
  });
  /**
 * @swagger
 * /testregister-staff:
 *   post:
 *     summary: Register a new staff.
 *     tags:
 *       - test
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username for the new staff member.
 *               password:
 *                 type: string
 *                 description: The password for the new staff member.
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '201':
 *         description: Successfully registered a new staff member.
 *       '400':
 *         description: Bad request, username already exists.
 *       '500':
 *         description: Internal Server Error.
 */
app.post('/testregister-staff', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if the username already exists in the "test" collection of "companyappointment" database
    const existingTest = await db.collection(testCollection).findOne({ username });

    if (existingTest) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new staff member
    const newTest = {
      username,
      password: hashedPassword,
    };

    // Insert the new staff member into the "test" collection of "companyappointment" database
    await db.collection(testCollection).insertOne(newTest);

    res.status(201).json({ message: 'Successfully registered a new staff member' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

  
    // Start the server
    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  })
  .catch((error) => {
    console.log('Error connecting to MongoDB:', error);
  });