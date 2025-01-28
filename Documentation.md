# Application Documentation

## Overview

The **Nest_Mongo_Template** is a GitHub template designed to help developers quickly start building new microservices for the MicoMotion ecosystem. It uses NestJS and MongoDB to offer a solid and efficient base, making the development process faster and simpler. This template comes with MongoDB, Swagger and RabbitMQ already set up, along with middleware for managing headers, allowing developers to focus on adding unique features right away.

This template follows best practices for creating microservices, such as effective data management, separating application logic, and ensuring security. With the initial setup for MongoDB, RabbitMQ, and header middleware, developers get a complete set of tools from the start. This speeds up development, improves the ability to handle more users, and boosts the performance of microservices in the MicoMotion ecosystem. **Nest_Mongo_Template** is the perfect starting point for developers looking for an easier way to create new microservices.

## Prerequisites

- Node.js (v14.17.0 or higher)
- npm (v6.14.13 or higher)
- A modern web browser

## Installation

To start a new microservice using the **Nest_Mongo_Template**, follow these steps:

1. **Create a New Repository on GitHub:**

- Go to GitHub and click on the "New repository" button.
- In the "Repository template" section, select `microMotion-ecosystem/nest_mongo_template`.
- For the repository name, follow the ecosystem standards: `api-[repoName]-service`. Make sure to replace `[repoName]` with your service's name, adhering to lowercase letters, using dashes (`-`) instead of underscores (`_`), and avoiding spaces.

2. **Clone the Repository:**

- Once the repository is created, clone it to your local machine using:
  ```bash
  git clone https://github.com/yourusername/api-[repoName]-service.git
  ```
- Replace `yourusername` with your GitHub username and `[repoName]` with the name of your service.

3. **Update the Application Name:**

- Navigate to the cloned repository's directory:
  ```bash
  cd api-[repoName]-service
  ```
- Find all instances of `<APP_NAME>` in your project files and replace them with your service's name, following the naming conventions mentioned above.

4. **Configure Environment Variables:**

- Copy or rename the `.env.temp` file to `.env`:
  ```bash
  cp .env.temp .env
  ```
- Open the `.env` file and update the environment configuration settings according to your service's requirements.

Following these steps will set up your new microservice project, ready for further development and customization.

### Installing Dependencies

```bash
npm install
```

## Configuration

Copy or rename the `.env.temp` file to `.env` in the root directory of your project. Replace the placeholders with your actual values.

### Environment Variables

- `PORT`: The port on which the application will run (e.g., 5502).
- `APP_ENV`: The application environment (e.g., development).
- `APP_NAME`: The name of your service (e.g., api-auth-service).
- `APP_VERSION`: 1.0.0
- `DB_USERNAME`: Your database username.
- `DB_PASSWORD`: Your database password.
- `DB_HOST`: Hostname for your database.
- `DB_NAME`: taskmaster_db
- `RABBITMQ_URL`: URL for connecting to RabbitMQ.
- `RABBITMQ_QUEUE_NAME`: MicroMotion (the name of the ecosystem)
- `JWT_SECRET`: A secret key for JWT.
- `JWT_EXPIRATION_TIME`: Expiration time for JWT tokens (e.g., 3600 for one hour).

## Running the Application

To start the application in development mode:

```bash
npm run dev
```

To start the application in production mode:

```bash
npm start
```

## Folder Structure

Below is the folder structure for the **Nest_Mongo_Template** project, designed to organize the codebase in a way that is easy to understand and navigate. Initially, the project is set up with a single module (`app.module.ts`) to serve the application's core functionality. If you need to add more modules for additional features or services, you can create separate folders within the `src/modules/` directory.

```
nest_mongo_template/
├── src/
│   ├── /controllers                 # Controllers that handle incoming HTTP requests
│   ├── /services                    # Services that contain business logic and application rules
│   ├── /core                        # Gards, Middlewares, Validators , Interceptors, Strategies, Filters, Pipes, Exceptions, etc...
│   ├── /api-services                # Services that interact with external APIs (Proxy)
│   ├── /repositories                # Data access layers that interact with the database
│   ├── /models                      # Data models that define the structure of database entities
│   ├── /dtos                        # Data Transfer Objects for handling and validating data input/output
│   ├── /config                      # Configuration files and environment variable management
├── .env                             # Environment variables file
├── .env.temp                        # Template for environment variables


```

This structure helps in maintaining a clean separation of concerns within the application, making it easier for developers to locate and manage specific parts of the codebase.

## Authentication

Authentication is handled via JWT tokens. Users receive a token upon login, which must be included in the header of subsequent requests to authenticate.

## Error Handling

Errors return a JSON object in the following format:

```json
{
  "error": "NotFoundError",
  "message": "The requested resource was not found."
}
```

Common errors include `NotFoundError` for missing resources and `ValidationError` for invalid input data.

## Testing

Run the application's tests with:

```bash
npm test
```

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.
