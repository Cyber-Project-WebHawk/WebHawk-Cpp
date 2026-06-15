# Stage 1 — Build
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    cmake git build-essential \
    libssl-dev libjsoncpp-dev \
    uuid-dev zlib1g-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/drogonframework/drogon /drogon \
    && cd /drogon \
    && git submodule update --init \
    && mkdir build && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_POSTGRESQL=ON \
    && make -j$(nproc) \
    && make install

WORKDIR /app
COPY . .

RUN mkdir build && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release \
    && make -j$(nproc)

# Stage 2 — Run
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libssl3 libjsoncpp25 libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/build/vulnerable_backend .

EXPOSE 9090
CMD ["./vulnerable_backend"]
