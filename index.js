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
  'mongodb+srv://alyaazafira:alyaazafira@alyaa.emy970i.mongodb.net/?retryWrites=true&w=majority';

// MongoDB database and collections names
const dbName = 'companyappointment';
const staffCollection = 'staff';
const securityCollection = 'security';
const appointmentCollection = 'appointments';

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
    const staffDB = db.collection(staffCollection);
    const securityDB = db.collection(securityCollection);
    const appointmentDB = db.collection(appointmentCollection);

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

      const { username, password } = req.body;

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
          username,
          password: hashedPassword,
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
  
      res.status(201).json({ token });
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

      const token = security.token || jwt.sign({ username, role: 'security' }, secretKey);
      securityDB
        .updateOne({ username }, { $set: { token } })
        .then(() => {
          res.status(200).json({ token });
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
    

    // Create appointment

/**
 * @swagger
 * /appointments:
 *   post:
 *     summary: Create Appointment
 *     description: Create a new appointment
 *     tags: [visitor]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
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
 *                 properties:
 *                   username:
 *                     type: string
 *     responses:
 *       '200':
 *         description: Appointment created successfully
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '500':
 *         description: Internal Server Error - Error creating appointment
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
        staff: { username },
      } = req.body;

      const appointment = {
        name,
        company,
        purpose,
        phoneNo,
        date,
        time,
        verification,
        staff: { username },
      };

      appointmentDB
        .insertOne(appointment)
        .then(() => {
          res.status(200).send('Appointment created successfully');
        })
        .catch((error) => {
          res.status(500).send('Error creating appointment');
        });
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
    app.get('/appointments', authenticateTokenForSecurity, async (req, res) => {
      const { name } = req.query;
      const { role } = req.user;
    
      if (role !== 'security') {
        return res.status(403).send('Invalid or unauthorized token');
      }
    
      const filter = name ? { name: { $regex: name, $options: 'i' } } : {};
    
      appointmentDB
        .find(filter)
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
  
    // Start the server
    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  })
  .catch((error) => {
    console.log('Error connecting to MongoDB:', error);
  });