FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /decision-engine .

FROM alpine:3.20
COPY --from=build /decision-engine /decision-engine
EXPOSE 7003
ENTRYPOINT ["/decision-engine"]
