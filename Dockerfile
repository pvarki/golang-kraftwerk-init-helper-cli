FROM golang:1.20.2-buster AS base

ENV \
    CGO_ENABLED=0 \
    GOOS=linux \
    LC_ALL=C.UTF-8

WORKDIR /app

RUN apt-get update && apt-get install -y \
  git \
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p -m 0700 ~/.ssh && ssh-keyscan github.com | sort > ~/.ssh/known_hosts

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .


# dev-shell ------------------------------

FROM base as dev_shell

WORKDIR /app

COPY . /app

RUN --mount=type=ssh apt-get update && apt-get install -y \
    zsh \
    python3 python3-pip python3-yaml \
    && sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" \
    && echo "source /root/.profile" >>/root/.zshrc \
    && pip3 install pre-commit \
    && true

ENTRYPOINT ["/bin/zsh", "-l"]


# builder ------------------------------

FROM base as builder

WORKDIR /app

# Build the kraftwerk
RUN go build -o cmd/kraftwerk main.go

# Move to /dist directory as the place for resulting binary folder
WORKDIR /dist

# Copy binary from build to main folder
RUN cp /app/cmd/kraftwerk .


# production ------------------------------

FROM scratch as production

COPY --from=builder /dist/kraftwerk /

# Command to run the executable
ENTRYPOINT ["/kraftwerk"]
