FROM golang
RUN mkdir -p /go/src/otdd.io/otdd-adapter
ADD . /go/src/otdd.io/otdd-adapter
WORKDIR /go/src/otdd.io/otdd-adapter
RUN go get ./...
RUN go install -v ./... 
CMD ["/go/bin/otdd-adapter"]
