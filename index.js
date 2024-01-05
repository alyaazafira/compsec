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

// Middleware for authentication and authorization
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send('Invalid or unauthorized token');
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

/**
     * @swagger
     * /register-staff:
     *   post:
     *     summary: Register staff
     *     tags: [security]
     *     security:
     *       - bearerAuth: []
     *     requestBody:
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
     *       200:
     *         description: Staff registered successfully
     *       403:
     *         description: Invalid or unauthorized token
     *       409:
     *         description: Username already exists
     *       500:
     *         description: Error registering staff
     */

    // Register staff
    app.post('/register-staff', authenticateToken, async (req, res) => {
      const { role } = req.user;

      if (role !== 'security') {
        return res.status(403).send('Invalid or unauthorized token');
      }

      const { username, password } = req.body;

      const existingStaff = await staffDB.findOne({ username });

      if (existingStaff) {
        return res.status(409).send('Username already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const staff = {
        username,
        password: hashedPassword,
      };

      staffDB
        .insertOne(staff)
        .then(() => {
          res.status(200).send('Staff registered successfully');
        })
        .catch(() => {
          res.status(500).send('Error registering staff');
        });
    });

    /**
     * @swagger
     * /register-security:
     *   post:
     *     summary: Register security
     *     tags: [security]
     *     requestBody:
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
     *       200:
     *         description: Security registered successfully
     *       409:
     *         description: Username already exists
     *       500:
     *         description: Error registering security
     */
    // Register security
    app.post('/register-security', async (req, res) => {
      const { username, password } = req.body;

      const existingSecurity = await securityDB.findOne({ username });

      if (existingSecurity) {
        return res.status(409).send('Username already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const security = {
        username,
        password: hashedPassword,
      };

      securityDB
        .insertOne(security)
        .then(() => {
          res.status(200).send('Security registered successfully');
        })
        .catch(() => {
          res.status(500).send('Error registering security');
        });
    });

    /**
     * @swagger
     * /login-staff:
     *   post:
     *     summary: Staff login
     *     tags: [Staff]
     *     requestBody:
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
     *       200:
     *         description: Staff logged in successfully
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 token:
     *                   type: string
     *       401:
     *         description: Invalid credentials
     *       500:
     *         description: Error storing token
     */

    // Staff login
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
     * /login-security:
     *   post:
     *     summary: Security login
     *     tags: [security]
     *     requestBody:
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
     *       200:
     *         description: Security logged in successfully
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 token:
     *                   type: string
     *       401:
     *         description: Invalid credentials
     *       500:
     *         description: Error storing token
     */
    // Security login
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

      const token = jwt.sign({ username, role: 'security' }, secretKey);
      securityDB
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
     * /appointments:
     *   post:
     *     summary: Create appointment
     *     tags: [visistor]
     *     requestBody:
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
     *       200:
     *         description: Appointment created successfully
     *       500:
     *         description: Error creating appointment
     */

    // Create appointment
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
        .catch(() => {
          res.status(500).send('Error creating appointment');
        });
    });

    /**
     * @swagger
     * /staff-appointments/{username}:
     *   get:
     *     summary: Get staff's appointments
     *     tags: [staff]
     *     security:
     *       - bearerAuth: []
     *     parameters:
     *       - name: username
     *         in: path
     *         description: Staff member's username
     *         required: true
     *         schema:
     *           type: string
     *     responses:
     *       200:
     *         description: List of staff's appointments
     *       403:
     *         description: Invalid or unauthorized token
     *       500:
     *         description: Error retrieving appointments
     */

    // Get staff's appointments
    app.get('/staff-appointments/:username', authenticateToken, async (req, res) => {
      const { username } = req.params;
      const { role, username: authenticatedUsername } = req.user;

      if (role !== 'staff') {
        return res.status(403).send('Invalid or unauthorized token');
      }

      if (username !== authenticatedUsername) {
        return res.status(403).send('Invalid or unauthorized token');
      }

      appointmentDB
        .find({ 'staff.username': username })
        .toArray()
        .then((appointments) => {
          res.json(appointments);
        })
        .catch(() => {
          res.status(500).send('Error retrieving appointments');
        });
    });

  
    // Start the server
    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  })
  .catch((error) => {
    console.log('Error connecting to MongoDB:', error);
  });