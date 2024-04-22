FROM gcc:latest

COPY main.c .

RUN gcc -pthread -o server main.c
RUN mv server bin/

ENTRYPOINT [ "server" ]

EXPOSE 80
