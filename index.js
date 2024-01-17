const express = require('express');
const mongodb = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const passwordValidator = require('password-validator');

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

//security register token
const SECURITY_REGISTRATION_TOKEN = '53cr377ok3n453cur1ty';

// Create a password schema for strong passwords
const passwordSchema = new passwordValidator();

// Add password rules (minimum length of 8 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character)
passwordSchema
  .is().min(8)
  .has().uppercase()
  .has().lowercase()
  .has().digits()
  .has().symbols();

// Middleware function to validate password strength
const validatePasswordStrength = (req, res, next) => {
  const { password } = req.body;

  // Validate the password against the schema
  if (!passwordSchema.validate(password)) {
    return res.status(400).json({ error: 'Bad request - Weak password. Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.' });
  }

  next();
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
app.post('/register-staff', authenticateTokenForSecurity, validatePasswordStrength, async (req, res) => {
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

////register security////
/**
 * @swagger
 * /register-security:
 *   post:
 *     summary: Register a new security member (Security Authorization Required).
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
 *                 description: The username of the security member.
 *               password:
 *                 type: string
 *                 description: The password of the security member.
 *               registrationToken:
 *                 type: string
 *                 description: The registration token for security member registration.
 *     responses:
 *       '201':
 *         description: Successfully registered a new security member.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Successfully registered a new security member
 *       '400':
 *         description: Bad request, username already exists.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Username already exists
 *       '401':
 *         description: Unauthorized, invalid or missing registration token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized registration
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
app.post('/register-security', validatePasswordStrength, async (req, res) => {
  try {
    const { username, password, registrationToken } = req.body;

    // Check if the registration token is valid
    if (registrationToken !== SECURITY_REGISTRATION_TOKEN) {
      return res.status(401).json({ error: 'Unauthorized registration' });
    }

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

    res.status(201).json({ message: 'Successfully registered a new security member' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

  

///// Security login////
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
/////change password/////
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
app.post('/change-password', validatePasswordStrength, async (req, res) => {
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

//create visitor appointment(without approval)
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


////// Get staff's appointments
/**
 * @swagger
 * /staff-appointments/{staffId}:
 *   get:
 *     summary: Get Staff Appointments
 *     description: Retrieve appointments for a specific staff member
 *     tags:
 *       - staff
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: staffId
 *         description: Id of the staff member
 *         required: true
 *         schema:
 *           type: number
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
 *                       staffId:
 *                         type: number
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

app.get('/staff-appointments/:staffId', authenticateToken, async (req, res) => {
  const { staffId } = req.params;
  const { role, username: requestingUsername } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  try {
    // Fetch the staff information based on staffId
    const staff = await staffDB.findOne({ staffId: parseInt(staffId) });

    // Check if the staff making the request matches the assigned staff for the appointment
    if (!staff || staff.username !== requestingUsername) {
      return res.status(403).send('Invalid or unauthorized token. Cannot get appointments of other staff');
    }

    // Continue with fetching appointments
    const appointments = await appointmentDB.find({ 'staff.staffId': staff.staffId }).toArray();
    res.json(appointments);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error retrieving appointments');
  }
});

///staff update verification////
/**
 * @swagger
 * /UPDATEappointments/{name}:
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
 *         description: Forbidden - Invalid or unauthorized token or attempting to update other staff's appointments
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
app.put('/UPDATEappointments/:name', authenticateToken, async (req, res) => {
  const { name } = req.params;
  const { verification } = req.body;
  const { role, username: requestingUsername } = req.user;

  try {
    // Ensure only staff can access this route
    if (role !== 'staff') {
      return res.status(403).send('Invalid or unauthorized token');
    }

    // Fetch the appointment details to get the staff assigned to it
    const appointment = await appointmentDB.findOne({ name });

    if (!appointment) {
      return res.status(500).send('Error updating appointment. Appointment not found');
    }
    
    const { staffid } = appointment;

    // Fetch the staff information based on staffid (assuming there's a function to do this)
    const staff = await getStaffByStaffId(staffid);
    
    // Check if the staff making the request matches the assigned staff for the appointment
    if (!staff || staff.username !== requestingUsername) {
      return res.status(403).send('Invalid or unauthorized token. Cannot UPDATE appointments of other staff');
    }

    // Continue with updating appointment verification
    await appointmentDB.updateOne({ name }, { $set: { verification } });
    res.status(200).send('Appointment verification updated successfully');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error updating appointment verification');
  }
});

    // Delete appointment
// Delete appointment
/**
 * @swagger
 * /appointments/{name}:
 *   delete:
 *     summary: Delete Appointment
 *     description: Delete an appointment by name. Only the staff member assigned to the appointment can delete it.
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
 *       '403':
 *         description: Forbidden - Invalid or unauthorized token or attempting to delete other staff's appointments
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
 */
app.delete('/appointments/:name', authenticateToken, async (req, res) => {
  const { name } = req.params;
  const { role, username: requestingUsername } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  try {
    // Fetch the appointment details to get the staff assigned to it
    const appointment = await appointmentDB.findOne({ name });

    if (!appointment) {
      return res.status(500).send('Error deleting appointment. Appointment not found');
    }

    const { staff } = appointment;

    // Check if the staff making the request matches the assigned staff for the appointment
    if (staff.username !== requestingUsername) {
      return res.status(403).send('Invalid or unauthorized token. Cannot delete appointments of other staff');
    }

    // If the staff matches, proceed with deleting the appointment
    appointmentDB
      .deleteOne({ name })
      .then(() => {
        res.status(200).send('Appointment deleted successfully');
      })
      .catch((error) => {
        res.status(500).send('Error deleting appointment');
      });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error deleting appointment');
  }
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
  
////register staff without authorization from security/////  
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
app.post('/testregister-staff', validatePasswordStrength, async (req, res) => {
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
////test login without security authorization///
/**
 * @swagger
 * /test-login-staff:
 *   post:
 *     summary: Login for Staff.
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
 *                 description: The username of the staff member.
 *               password:
 *                 type: string
 *                 description: The password of the staff member.
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Login successful. Returns the JWT token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       '401':
 *         description: Unauthorized - Invalid credentials.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid credentials
 *       '500':
 *         description: Internal Server Error - Error storing token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 */
app.post('/test-login-staff', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find the staff member in the "test" collection of "companyappointment" database
    const staff = await db.collection(testCollection).findOne({ username });

    if (!staff) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if the provided password matches the hashed password stored in the database
    const passwordMatch = await bcrypt.compare(password, staff.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate a JWT token for staff
    const token = jwt.sign({ username, role: 'staff' }, secretKey);

    // Update the staff member with the generated token
    await db.collection(testCollection).updateOne({ _id: staff._id }, { $set: { token } });

    res.status(200).json({ token });
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