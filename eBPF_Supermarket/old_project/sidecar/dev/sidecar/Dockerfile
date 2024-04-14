# Use the Go v1.18 image for the base.
FROM golang:1.18

# Copy the proxy code to the container.
COPY main.go .

RUN go build -o sidecar main.go
RUN mv sidecar bin/
RUN ls bin

# Run the proxy on container startup.
ENTRYPOINT [ "sidecar" ]

# Expose the proxy port.
EXPOSE 8000
