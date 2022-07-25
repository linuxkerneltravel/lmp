# Use the latest Ubuntu image for the base.
FROM ubuntu:latest

# Install the iptables command.
RUN apt-get update && \
    apt-get install -y iptables

# Copy the initialization script into the container.
COPY net-init.sh /usr/local/bin/

# Mark the initialization script as executable.
RUN chmod +x /usr/local/bin/net-init.sh

# Start the initialization script on container startup.
ENTRYPOINT ["net-init.sh"]