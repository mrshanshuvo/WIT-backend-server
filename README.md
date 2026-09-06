# WhereIsIt — Backend

WhereIsIt Backend is the REST API powering the WhereIsIt lost and found platform.

It provides authentication, user operations, lost and found item management, recovery workflows, and application content APIs backed by MongoDB.

## API

Deployed API:

[WhereIsIt Backend](https://whereisit-server-inky.vercel.app)

## Features

* User authentication and authorization
* Firebase authentication integration
* JWT-based authentication
* User profile management
* Lost and found item management
* Create, read, update, and delete item operations
* Recovery management
* Protected API routes
* Blog data management
* FAQ management
* Contact information management
* Homepage slide/content management
* MongoDB data storage
* CORS configuration
* Secure password handling with bcrypt

## Tech Stack

### Backend

* Node.js
* Express.js
* JavaScript
* REST API

### Database

* MongoDB
* MongoDB Native Driver

### Authentication & Security

* Firebase Admin
* JWT
* bcryptjs
* cookie-parser

### Other Tools

* Multer
* CORS
* dotenv
* Vercel

## API Structure

The API is organized around several main resources:

```text
/users
/inventory
/recoveries
```

### Users

Handles user-related operations including:

* User profile
* Firebase login
* Logout
* User data management

### Inventory

Handles lost and found item operations including:

* Create items
* Retrieve items
* Update items
* Delete items
* Retrieve individual item details

### Recoveries

Handles item recovery workflows including:

* Recovery records
* Recovery status
* Updating recovery information
* Protected recovery operations

## Authentication

Protected endpoints require authentication.

The backend integrates with Firebase Admin for authentication verification and uses JWT-based authorization for protected API operations.

Authentication-related operations include:

* Firebase login
* JWT generation and verification
* Protected routes
* User authorization
* Logout

## Database

WhereIsIt uses MongoDB as its primary database.

The application uses the MongoDB native driver for database operations and `ObjectId` for MongoDB document identification.

## Getting Started

### Prerequisites

Make sure you have the following installed:

* Node.js
* npm
* MongoDB database

### Installation

Clone the repository:

```bash
git clone https://github.com/mrshanshuvo/whereisit-backend.git
```

Navigate to the project:

```bash
cd whereisit-backend
```

Install dependencies:

```bash
npm install
```

Configure the required environment variables and start the server.

```bash
npm start
```

For development, use the appropriate development script configured in `package.json`.

## Environment Variables

Create a `.env` file in the project root.

Configure the required values for:

```env
PORT=your_port
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
```

Firebase Admin credentials and other application-specific configuration should also be provided through environment variables.

Never commit credentials, secrets, or `.env` files to the repository.

## Project Architecture

The backend follows a REST API architecture with separate responsibilities for:

```text
Client
   │
   ▼
Express REST API
   │
   ├── Authentication
   ├── Users
   ├── Inventory
   ├── Recoveries
   └── Content APIs
   │
   ▼
MongoDB
```

## Frontend

The API is consumed by the WhereIsIt frontend application.

Frontend repository:

[WhereIsIt Frontend](https://github.com/mrshanshuvo/whereisit-frontend)

## Deployment

The backend is deployed on Vercel.

API:

https://whereisit-server-inky.vercel.app

## License

This project is for educational and portfolio purposes.
