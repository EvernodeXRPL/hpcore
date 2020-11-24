FROM node:12.18.3-buster-slim

WORKDIR /text_client

COPY package*.json ./
RUN npm install

COPY text-client.js ./
COPY hp-client-lib.js ./

ENTRYPOINT ["node", "text-client.js"]

# Comment this for localhost connection.
# Client connects to node1 of the cluster.
CMD ["node1", "8081"]