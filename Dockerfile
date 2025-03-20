# Generated by https://smithery.ai. See: https://smithery.ai/docs/config#dockerfile
FROM node:lts-alpine

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --ignore-scripts

# Install missing dependency dotenv
RUN npm install dotenv

# Copy the rest of the project files
COPY . .

# Build the project
RUN npm run build

# Start the server using the provided SHODAN_API_KEY env variable
CMD ["npm", "start", "--", "--api-key", "${SHODAN_API_KEY}"]
