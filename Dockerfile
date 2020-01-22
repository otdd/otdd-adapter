FROM centos:7
COPY ./otdd-adapter/otdd-adapter /usr/local/bin/
WORKDIR /usr/local/bin/
CMD ["/usr/local/bin/otdd-adapter"]
