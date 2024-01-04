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
const authenticateToken= (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err){
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

//register security
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
    // Start the server
    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  })
  .catch((error) => {
    console.log('Error connecting to MongoDB:', error);
  });

  //register staff
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
    .catch((error) => {
      res.status(500).send('Error registering staff');
    });
});