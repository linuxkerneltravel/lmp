FROM ubuntu:jammy

RUN apt update -y

RUN apt install siege -y

ENTRYPOINT ["siege"]