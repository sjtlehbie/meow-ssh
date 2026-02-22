FROM rust:bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y openssh-client ca-certificates bash sudo && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash dev && echo "dev ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

COPY --from=builder /build/target/release/meow-ssh /usr/local/bin/meow-ssh

EXPOSE 2222 3000

CMD ["meow-ssh", "--domain", "localhost", "--ssh-port", "2222", "--web-port", "3000", "--host-key", "/data/meow_host_key", "--db", "/data/meow.db", "--shell-user", "dev", "--shell-home", "/home/dev"]
