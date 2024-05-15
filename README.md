# Portal Backend

## Overview

The Portal Backend is a Flask API application written in Python that serves as the communication layer between the frontend and various backend services. It facilitates user management, team/organization account management, endpoint generation, retrieval of supported chains, and analytics data.

## Functionality

1. **User Account Management**:
   - Allows for the creation and management of user accounts.
   - Data stored in the `users` table in the MySQL database.

2. **Team/Organization Account Management**:
   - Facilitates the creation and management of team/organization accounts.
   - Information stored in the `organisation` table in the MySQL database.

3. **Endpoint Generation**:
   - Generates endpoints for various functionalities.

4. **Supported Chains**:
   - Returns a list of supported chains.
   - Data retrieved from the `chains` table in the MySQL database.

5. **Usage Analytics**:
   - Provides usage analytics data.
   - Cached past usage data stored in the `analytics_cache` table in the MySQL database.
   - Connects to a Prometheus server to serve analytics/usage info.

## Database Structure

The application is connected to a MySQL database with the following tables:

1. **users**: Holds user information.
2. **organisation**: Holds organization/team info.
3. **api_keys**: Holds API key info.
4. **analytics_cache**: Cache of past usage data.
5. **chains**: Holds supported chains.

## Technologies Used

- **Python**: Programming language used for backend logic.
- **Flask**: Web framework for building the API endpoints.
- **MySQL**: Relational database for storing application data.
- **Prometheus**: Monitoring and analytics tool for serving usage analytics data.

## Setup and Configuration

1. Install Python and required dependencies.
2. Set up a MySQL database and configure database connection details in the application.
3. Install and configure Prometheus server for serving analytics data.
4. Deploy the Flask API application.
5. Ensure proper authentication and authorization mechanisms are in place for user/team management and API key generation.

## API Documentation

Detailed API documentation including endpoints, parameters, and responses can be found in the Swagger specification provided in the codebase.

## Contact Information

For any inquiries or support, please contact [support@liquify.io](mailto:support@liquify.io).
