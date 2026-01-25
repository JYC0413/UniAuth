# UniAuth

UniAuth is a lightweight authentication and authorization service built with Go (Golang) and the Gin web framework. It provides a RESTful API for user registration, login, and session management using JWT (JSON Web Tokens), along with a simple frontend for demonstration purposes.

## Features

- **User Authentication**: Register and Login functionality.
- **JWT Support**: Secure API endpoints using JSON Web Tokens.
- **Role/Permission Management**: (Basic structure included).
- **Database Integration**: Uses PostgreSQL with GORM for object-relational mapping.
- **Frontend**: Includes a basic HTML/JS frontend to interact with the API.

## Prerequisites

Before you begin, ensure you have the following installed on your machine:

- [Go](https://go.dev/dl/) (Version 1.24 or later)
- [PostgreSQL](https://www.postgresql.org/download/)

## Getting Started

Follow these steps to set up and run the project locally.

### 1. Clone the Repository

```bash
git clone <repository-url>
cd UniAuth
```

### 2. Database Setup

Ensure you have a PostgreSQL database running. You can create a new database for this project (e.g., `uniauth`).

### 3. Configuration

Create a `.env` file in the root directory of the project to configure your environment variables. You can use the following template:

```env
# Server Configuration
SERVER_PORT=8080

# Database Configuration
# Option 1: Use a full connection string (Recommended)
DATABASE_URL=postgresql://username:password@localhost:5432/uniauth

# Option 2: Use individual parameters (if DATABASE_URL is not set)
# DB_HOST=localhost
# DB_USER=postgres
# DB_PASSWORD=your_password
# DB_NAME=uniauth
# DB_PORT=5432

# Security
JWT_SECRET=your_secure_random_secret_key
```

### 4. Install Dependencies

Download the required Go modules:

```bash
go mod tidy
```

### 5. Run the Application

Start the server:

```bash
go run main.go
```

You should see output indicating the server is running, for example:
`Server starting on port 8080`

## Usage

### Frontend

Once the server is running, you can access the web interface at:

- **Home**: [http://localhost:8080/](http://localhost:8080/)
- **Dashboard**: [http://localhost:8080/dashboard](http://localhost:8080/dashboard)

### API Endpoints

The following API endpoints are available:

**Public Routes:**
- `POST /api/v1/auth/register`: Register a new user.
- `POST /api/v1/auth/login`: Login and receive a JWT.
- `POST /api/v1/auth/logout`: Logout (client-side token removal).
- `GET /api/v1/meta/permissions`: Get list of permissions.

**Protected Routes (Requires Bearer Token):**
- `GET /api/v1/auth/my-mask`: Get current user's permission mask.

## Project Structure

- `main.go`: Application entry point and router setup.
- `internal/`: Contains the core application logic.
  - `config/`: Configuration loading.
  - `database/`: Database connection and setup.
  - `handler/`: HTTP request handlers (controllers).
  - `middleware/`: Auth middleware.
- `web/`: Static HTML and frontend assets.
