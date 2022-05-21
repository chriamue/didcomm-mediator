FROM rust:1.61.0-buster AS builder
WORKDIR /usr/src/

RUN USER=root cargo new --lib didcomm_mediator
WORKDIR /usr/src/didcomm_mediator
COPY Cargo.toml Cargo.lock ./
RUN echo "fn main() {}" > src/bin.rs
RUN mkdir examples
RUN touch examples/didexchange.rs
RUN touch examples/discoverfeatures.rs
RUN touch examples/invitation.rs
RUN touch examples/ping.rs
RUN cargo build --release
RUN rm src/*.rs
COPY src ./src
RUN touch src/lib.rs
RUN touch src/bin.rs
RUN cargo build --release
RUN ls target/release/

FROM rust:1.61.0-slim-buster

COPY --from=builder /usr/src/didcomm_mediator/target/release/didcomm-mediator /bin
USER 1000
COPY Rocket.toml ./Rocket.toml
CMD [ "didcomm-mediator" ]
