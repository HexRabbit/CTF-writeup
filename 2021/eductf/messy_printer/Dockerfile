FROM ubuntu:20.04
MAINTAINER fweasd
WORKDIR /
RUN apt update 
RUN apt install -y libssl-dev xinetd python2.7
RUN apt autoremove && apt autoclean 
RUN useradd -m messy_printer
COPY ./src/home /home/messy_printer
COPY ./xinetd /etc/xinetd.d/xinetd

RUN chown -R root:root /home/messy_printer && \
    chown -R root:root /etc/xinetd.d/xinetd && \
    find / -type d -perm /0002 -exec chmod o-w {} + 2>/dev/null ; \
    find / -type f -perm /0002 -exec chmod o-w {} + 2>/dev/null ; \
    echo 'Finish'

CMD ["/usr/sbin/xinetd","-dontfork"]
