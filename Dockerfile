FROM rust:alpine AS builder
WORKDIR /app
COPY . .
RUN cargo build --release
COPY /app/target/release/encrypted_folders /app/encrypted_folders

FROM scratch AS export-stage
COPY --from=builder /app/encrypted_folders /