FROM ubuntu:24.04@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

ENV user r2s
ENV chall_port 7138

RUN apt-get update
RUN apt-get -y install socat build-essential

RUN adduser $user

ADD ./flag /home/$user/flag
ADD ./$user /home/$user/$user

RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/$user

RUN chmod 755 /home/$user/$user
RUN chmod 440 /home/$user/flag

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD socat -T 30 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user
