# Use an official Node.js image as the base image (OWASP A06:2024 - Vulnerable and Outdated Components)
FROM node:18-alpine

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 8081

# Specify the user to run the application (OWASP A04:2024 - Insecure Design)
# This mitigates risks by not running the container as root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Run the application
CMD ["node", "server.js"]
