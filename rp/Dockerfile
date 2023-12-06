FROM golang:1.21

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /zitadel-oidc-example

EXPOSE 3000

ENV CLIENT_ID="myclient"
ENV CLIENT_SECRET="1e3fpb2S0JDZ8TlQu3LfIyUIgKdJCxRK"

CMD ["/zitadel-oidc-example"]
